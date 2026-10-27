// SPDX-License-Identifier: GPL-2.0-or-later
// Ordinary desktop presentation state; never authorization or file ownership.
#pragma once

#include <QDir>
#include <QCryptographicHash>
#include <QFileInfo>
#include <QHash>
#include <QSettings>
#include <QStringList>
#include <QUrl>

namespace Greyward {

class DesktopOutputLayout {
public:
    explicit DesktopOutputLayout(const QString& file) : file_(file) {
        QSettings settings(file_, QSettings::IniFormat);
        settings.beginGroup(QStringLiteral("Items"));
        for(const auto& key : settings.childKeys()) {
            const auto name = QString::fromUtf8(QByteArray::fromBase64(key.toLatin1(), QByteArray::Base64UrlEncoding));
            if(validName(name)) {
                owners_.insert(name, settings.value(key).toString());
            }
        }
    }

    QString owner(const QString& name, const QStringList& screens, const QString& primary) {
        const auto preferred = owners_.value(name);
        if(!preferred.isEmpty() && screens.contains(preferred)) {
            return preferred;
        }
        // A disconnected output keeps its saved preference. Show the icon on
        // exactly one available output until that output returns.
        const auto fallback = screens.contains(primary) ? primary
            : screens.isEmpty() ? QString() : screens.first();
        if(preferred.isEmpty() && !fallback.isEmpty()) {
            // Remember the first placement too: changing the primary output
            // must not move every icon which was never manually dragged.
            assign({name}, fallback, screens);
        }
        return fallback;
    }

    static QString positionFile(const QString& profile, const QString& screen, QStringList screens) {
        screens.removeDuplicates();
        screens.sort(Qt::CaseSensitive);
        QByteArray identity;
        for(const auto& output : screens) {
            // Length-prefix names so neither separators nor enumeration order
            // can alias another connected-output configuration.
            const auto bytes = output.toUtf8();
            identity += QByteArray::number(bytes.size()) + ':' + bytes;
        }
        const auto key = QCryptographicHash::hash(identity, QCryptographicHash::Sha256).toHex();
        return QDir(profile).filePath(QStringLiteral("desktop-layout-%1-%2.conf")
            .arg(QString::fromLatin1(key), keyFor(screen)));
    }

    bool assign(const QStringList& names, const QString& screen, const QStringList& available) {
        if(screen.isEmpty() || !available.contains(screen) || names.isEmpty()) {
            return false;
        }
        for(const auto& name : names) {
            if(!validName(name)) {
                return false;
            }
        }
        QSettings settings(file_, QSettings::IniFormat);
        settings.setAtomicSyncRequired(true);
        settings.beginGroup(QStringLiteral("Items"));
        for(const auto& name : names) {
            settings.setValue(keyFor(name), screen);
        }
        settings.endGroup();
        settings.sync();
        if(settings.status() != QSettings::NoError) {
            return false;
        }
        for(const auto& name : names) {
            owners_.insert(name, screen);
        }
        return true;
    }

    void renamed(const QString& before, const QString& after) {
        if(before == after || !validName(after) || !owners_.contains(before)) {
            return;
        }
        QSettings settings(file_, QSettings::IniFormat);
        settings.setAtomicSyncRequired(true);
        settings.beginGroup(QStringLiteral("Items"));
        settings.setValue(keyFor(after), owners_.value(before));
        settings.remove(keyFor(before));
        settings.endGroup();
        settings.sync();
        if(settings.status() == QSettings::NoError) {
            owners_.insert(after, owners_.take(before));
        }
    }

    // A drag of existing Desktop entries onto another Desktop is a layout
    // change, not a copy/delete operation. Mixed or external files stay with
    // the existing native file-operation workflow.
    static QStringList desktopDropItems(const QList<QUrl>& urls, const QString& desktop) {
        const auto directory = QFileInfo(desktop).canonicalFilePath();
        if(directory.isEmpty() || urls.isEmpty()) {
            return {};
        }
        QStringList names;
        for(const auto& url : urls) {
            const QFileInfo item(url.toLocalFile());
            if(!url.isLocalFile() || (!item.exists() && !item.isSymLink())
               || QFileInfo(item.absolutePath()).canonicalFilePath() != directory
               || !validName(item.fileName())) {
                return {};
            }
            if(!names.contains(item.fileName())) {
                names.append(item.fileName());
            }
        }
        return names;
    }

private:
    static bool validName(const QString& name) {
        return !name.isEmpty() && name != QLatin1String(".") && name != QLatin1String("..")
            && !name.contains(QLatin1Char('/')) && !name.contains(QChar::Null);
    }
    static QString keyFor(const QString& name) {
        return QString::fromLatin1(name.toUtf8().toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
    }
    QString file_;
    QHash<QString, QString> owners_;
};
}
