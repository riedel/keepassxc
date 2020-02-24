/*
 *  Copyright (C) 2014 Kyle Manna <kyle@kylemanna.com>
 *  Copyright (C) 2017 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>


#include "core/Global.h"
#include "core/Tools.h"
#include "crypto/Random.h"

#include "YubiKey.h"

extern "C" {
#include "fido.h"
}

// Cast the void pointer from the generalized class definition
// to the proper pointer type from the now included system headers

#define MAX_DEVICES_TO_LIST 20


YubiKey::YubiKey() 
    :  m_dev(nullptr)
    ,  m_mutex(QMutex::Recursive)
{
}

YubiKey* YubiKey::m_instance(Q_NULLPTR);

YubiKey* YubiKey::instance()
{
    if (!m_instance) {
        m_instance = new YubiKey();
    }

    return m_instance;
}

bool YubiKey::init()
{
    m_mutex.lock();

// previously initialized
    
    if (m_dev != nullptr) {
	    //TODO: ping?
        return true;
    }

    fido_dev_info_t *devlist = fido_dev_info_new(MAX_DEVICES_TO_LIST);
    size_t ndevs;

    fido_dev_info_manifest(devlist, MAX_DEVICES_TO_LIST, &ndevs);

    for (size_t i = 0; i < ndevs ; i++) {
	    const fido_dev_info_t *di = fido_dev_info_ptr(devlist, i);
	    fido_dev_t *dev = fido_dev_new();
	    fido_dev_open(dev,fido_dev_info_path(di));

        fido_cbor_info_t * cbor= fido_cbor_info_new();
	    fido_dev_get_cbor_info(dev, cbor);
	    
	    char *const *extensions = fido_cbor_info_extensions_ptr(cbor);
	    size_t extensions_length = fido_cbor_info_extensions_len(cbor);

	    for (size_t j = 0; j < extensions_length; j++) {
		    if (strcmp("hmac-secret", extensions[j]) == 0) {
			    m_dev = dev;
		    }
	    }

	    fido_cbor_info_free(&cbor);

	    if (m_dev==nullptr) fido_dev_close(dev);
	    else break;
    }

    fido_dev_info_free(&devlist,MAX_DEVICES_TO_LIST);

    if (m_dev == nullptr) {
	    deinit();
	    m_mutex.unlock();
	    return false;
    }

    m_mutex.unlock();
    return true;
}

bool YubiKey::deinit()
{
	m_mutex.lock();

	fido_dev_close(m_dev);

	m_mutex.unlock();

	return true;
}

void YubiKey::detect()
{

    emit detected(0, true);
    emit detectComplete();
}

bool YubiKey::checkSlotIsBlocking(int slot, QString& errorMessage)
{
	if (!init()) {
		errorMessage = QString("Could not initialize YubiKey.");
		return false;
	}
    if(slot!=0)
        qWarning("Unknown slot ?");
    //I guess we always need to touch
	return true;
}


bool YubiKey::getSerial(unsigned int& serial)
{
	//TODO
	serial=42;

	return true;
}

QString YubiKey::getVendorName()
{
	//TODO 
	return "FIDO2";
        //return	fido_dev_info_manufacturer_string(m_dev);
}

YubiKey::ChallengeResult YubiKey::challenge(int slot, bool mayBlock, const QByteArray& unpaddedChallenge, QByteArray& response)
{
	// ensure that YubiKey::init() succeeded
	if (!init()) {
		return ERROR;
	}

    if (slot!=0)
        qWarning("No slots supported!!");

    if (!mayBlock) {
        qFatal("Is it a problem that we may not block?");
        return ERROR;
    }


	QByteArray paddedChallenge = unpaddedChallenge;

	// yk_challenge_response() insists on 64 bytes response buffer */
	response.clear();
	response.resize(64);

	/* The challenge sent to the yubikey should always be 64 bytes for
	 * compatibility with all configurations.  Follow PKCS7 padding.
	 *
	 * There is some question whether or not 64 bytes fixed length
	 * configurations even work, some docs say avoid it.
	 */

    const int padLen = 32 - paddedChallenge.size();
	if (padLen > 0) {
		paddedChallenge.append(QByteArray(padLen, padLen));
	}

	const unsigned char* challenge;
	challenge = reinterpret_cast<const unsigned char*>(paddedChallenge.constData());

	// Try to grab a lock for 1 second, fail out if not possible
	if (!m_mutex.tryLock(1000)) {
		return ALREADY_RUNNING;
	}

	int r;


	fido_assert_t *assert;

	if ((assert = fido_assert_new()) == NULL)
    {
        qCritical("fido_assert_new");
        return ERROR;
    }

    if ((r = fido_assert_set_clientdata_hash(assert, challenge,
          paddedChallenge.size())) != FIDO_OK ||
			(r = fido_assert_set_rp(assert,"keepassxc.org" )) != FIDO_OK)
    {
        qCritical("fido_assert_set: %s", fido_strerr(r));
        fido_assert_free(&assert);return ERROR;
    }

	if ((r = fido_assert_set_extensions(assert,
					FIDO_EXT_HMAC_SECRET)) != FIDO_OK)
    {
        qCritical("fido_assert_set_extensions: %s",
				fido_strerr(r));
        fido_assert_free(&assert);return ERROR;
    }

	if ((r = fido_assert_set_hmac_salt(assert, challenge,
                    paddedChallenge.size())) != FIDO_OK)
    {
        qCritical("fido_assert_set_hmac_salt: %s",
				fido_strerr(r));
        fido_assert_free(&assert);return ERROR;
    }

	if ((r = fido_dev_get_assert(m_dev,assert,NULL)) != FIDO_OK )
    {
        qCritical("fido_assert_get_assert: %s",fido_strerr(r));
        fido_assert_free(&assert);return ERROR;
    }

    size_t len=fido_assert_hmac_secret_len(assert, 0);
    response.resize(len);
    response.replace(0,len,reinterpret_cast<const char *>(fido_assert_hmac_secret_ptr(assert, 0)));
	fido_assert_free(&assert);


	// actual HMAC-SHA1 response is only 20 bytes
    //

	return SUCCESS;
}
