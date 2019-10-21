/*
 *  Copyright (C) 2014 Felix Geyer <debfx@fobos.de>
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

#ifndef KEEPASSX_PASSWORDEDIT_H
#define KEEPASSX_PASSWORDEDIT_H

#include <QAction>
#include <QLineEdit>
#include <QPointer>

class QTimer;

class PasswordEdit : public QLineEdit
{
    Q_OBJECT

public:
    static const QColor CorrectSoFarColor;
    static const QColor ErrorColor;

    explicit PasswordEdit(QWidget* parent = nullptr);
    void enableVerifyMode(PasswordEdit* baseEdit);
    bool isPasswordVisible() const;

public slots:
    void setShowPassword(bool show);

protected:
    void showEvent(QShowEvent* event) override;
    void hideEvent(QHideEvent* event) override;

signals:
    void showPasswordChanged(bool show);
    void capslockToggled(bool capslockOn);

private slots:
    void updateStylesheet();
    void autocompletePassword(const QString& password);
    void checkCapslockState();

private:
    bool passwordsEqual() const;

    bool m_capslockState = false;
    QPointer<QAction> m_errorAction;
    QPointer<QAction> m_correctAction;
    QPointer<PasswordEdit> m_basePasswordEdit;
    QPointer<QTimer> m_capslockPollTimer;
};

#endif // KEEPASSX_PASSWORDEDIT_H
