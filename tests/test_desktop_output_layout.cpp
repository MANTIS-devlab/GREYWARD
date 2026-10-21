// SPDX-License-Identifier: GPL-2.0-or-later
#include "../environment/session/desktop/output-layout.h"
#include <QCoreApplication>
#include <QFile>
#include <QTemporaryDir>
#include <iostream>
#include <stdexcept>

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QTemporaryDir temporary;
    if(!temporary.isValid()) return 1;
    int checks = 0;
    auto check = [&](bool result) {
        ++checks;
        if(!result) throw std::runtime_error("desktop layout check " + std::to_string(checks));
    };
    const auto file = temporary.filePath(QStringLiteral("outputs.conf"));
    const QString laptop = QStringLiteral("eDP-1"), left = QStringLiteral("HDMI-A-1"), right = QStringLiteral("DP-2");
    const QStringList screens{laptop, left, right};
    Greyward::DesktopOutputLayout layout(file);
    check(layout.owner(QStringLiteral("unassigned"), screens, laptop) == laptop);
    check(layout.assign({QStringLiteral("alpha.desktop")}, left, screens));
    check(layout.assign({QStringLiteral("beta.txt")}, right, screens));
    check(layout.owner(QStringLiteral("alpha.desktop"), screens, laptop) == left);
    check(layout.owner(QStringLiteral("beta.txt"), screens, laptop) == right);
    // An icon is visible once, including fallback while an output is absent.
    for(const auto& active : {screens, QStringList{laptop, right}, QStringList{right}, QStringList{}}) {
        int visible = 0;
        for(const auto& output : active) visible += layout.owner(QStringLiteral("alpha.desktop"), active, laptop) == output;
        check(visible == (active.isEmpty() ? 0 : 1));
    }
    check(layout.owner(QStringLiteral("alpha.desktop"), screens, laptop) == left);
    Greyward::DesktopOutputLayout reopened(file);
    check(reopened.owner(QStringLiteral("alpha.desktop"), screens, laptop) == left);
    check(reopened.owner(QStringLiteral("alpha.desktop"), {right, left, laptop}, laptop) == left);
    reopened.renamed(QStringLiteral("alpha.desktop"), QStringLiteral("résumé.desktop"));
    Greyward::DesktopOutputLayout renamed(file);
    check(renamed.owner(QStringLiteral("résumé.desktop"), screens, laptop) == left);
    check(renamed.owner(QStringLiteral("alpha.desktop"), screens, laptop) == laptop);
    check(!renamed.assign({QStringLiteral("../escape")}, left, screens));
    check(!renamed.assign({QStringLiteral("beta.txt")}, QStringLiteral("missing"), screens));
    check(renamed.owner(QStringLiteral("beta.txt"), screens, laptop) == right);
    const auto desktop = temporary.filePath(QStringLiteral("Desktop"));
    QDir().mkpath(desktop);
    const auto existing = desktop + QStringLiteral("/example.txt");
    QFile created(existing);
    check(created.open(QIODevice::WriteOnly));
    created.write("synthetic layout test");
    created.close();
    const auto original = QFileInfo(existing).size();
    check(Greyward::DesktopOutputLayout::desktopDropItems({QUrl::fromLocalFile(existing)}, desktop) == QStringList{QStringLiteral("example.txt")});
    check(Greyward::DesktopOutputLayout::desktopDropItems({QUrl(QStringLiteral("https://example.invalid/file"))}, desktop).isEmpty());
    check(Greyward::DesktopOutputLayout::desktopDropItems({QUrl::fromLocalFile(file)}, desktop).isEmpty());
    check(Greyward::DesktopOutputLayout::desktopDropItems({QUrl::fromLocalFile(existing), QUrl::fromLocalFile(file)}, desktop).isEmpty());
    check(QFileInfo(existing).size() == original && QDir(desktop).entryList(QDir::Files).size() == 1);
    std::cout << checks << " desktop layout checks passed\n";
}
