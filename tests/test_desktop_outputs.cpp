// SPDX-License-Identifier: GPL-2.0-or-later
// Explicit integration driver linked to the patched PCManFM objects. Run only
// in the private three-output headless session described by the test runner.
#include <QApplication>
#include <QDir>
#include <QDragEnterEvent>
#include <QDragMoveEvent>
#include <QDropEvent>
#include <QElapsedTimer>
#include <QFile>
#include <QListView>
#include <QMimeData>
#include <QProcess>
#include <QThread>
#include <QTimer>
#include <LayerShellQt/window.h>
#include "application.h"
#include "desktopwindow.h"
#include <functional>
#include <iostream>
#include <stdexcept>

static void require(bool result, const char* reason) {
    if(!result) throw std::runtime_error(reason);
}

static void until(const std::function<bool()>& predicate, const char* reason) {
    QElapsedTimer timer;
    timer.start();
    do {
        QApplication::processEvents(QEventLoop::AllEvents, 20);
        if(predicate()) return;
        QThread::msleep(10);
    } while(timer.elapsed() < 10000);
    throw std::runtime_error(reason);
}

static QHash<QString, PCManFM::DesktopWindow*> desktops() {
    QHash<QString, PCManFM::DesktopWindow*> result;
    for(auto widget : QApplication::topLevelWidgets()) {
        if(auto desktop = qobject_cast<PCManFM::DesktopWindow*>(widget)) {
            require(!result.contains(desktop->screenName()), "duplicate desktop surface");
            result.insert(desktop->screenName(), desktop);
        }
    }
    return result;
}

static bool contains(const QString& screen, const QString& file) {
    auto window = desktops().value(screen);
    if(!window) return false;
    auto list = window->findChild<QListView*>();
    if(!list || !list->model()) return false;
    for(int i = 0; i < list->model()->rowCount(); ++i) {
        if(list->model()->index(i, 0).data(Qt::DisplayRole).toString() == file) return true;
    }
    return false;
}

static int appearances(const QString& file) {
    int total = 0;
    const auto windows = desktops();
    for(auto it = windows.cbegin(); it != windows.cend(); ++it) total += contains(it.key(), file);
    return total;
}

int main(int argc, char** argv) {
    require(qEnvironmentVariable("GREYWARD_SYNTHETIC_DESKTOP_TEST") == QStringLiteral("three-headless-outputs"), "synthetic test guard missing");
    require(qEnvironmentVariable("XDG_RUNTIME_DIR").contains(QStringLiteral("greyward-desktop-test-")), "private runtime missing");
    qunsetenv("QT_NO_GLIB"); // match the production main
    PCManFM::Application app(argc, argv);
    app.init();
    QTimer::singleShot(0, &app, [&] {
        try {
            until([&] { return app.desktopOutputNames().size() == 3 && desktops().size() == 3; }, "three mapped outputs unavailable");
            const auto names = app.desktopOutputNames();
            const auto primary = app.primaryScreen()->name();
            const auto external = names.at(1);
            const auto target = names.at(2);
            until([&] { return contains(primary, QStringLiteral("alpha.txt")) && appearances(QStringLiteral("alpha.txt")) == 1; }, "initial icon duplicated or absent");
            for(auto window : desktops()) {
                require(window->getDesktopScreen() != nullptr, "output binding absent");
                require(LayerShellQt::Window::get(window->windowHandle())->layer() == LayerShellQt::Window::LayerBottom, "icons share wallpaper layer");
            }
            require(app.moveDesktopItems({QStringLiteral("alpha.txt")}, external), "screen reassignment failed");
            until([&] { return contains(external, QStringLiteral("alpha.txt")) && appearances(QStringLiteral("alpha.txt")) == 1; }, "reassignment not reflected in actual models");
            std::cout << "PASS three surfaces, independent layer, unique icon ownership\n";

            auto list = desktops().value(target)->findChild<QListView*>();
            require(list != nullptr, "target icon view missing");
            QMimeData mime;
            const auto path = qEnvironmentVariable("HOME") + QStringLiteral("/Desktop/alpha.txt");
            mime.setUrls({QUrl::fromLocalFile(path)});
            QDragEnterEvent enter(QPoint(400, 200), Qt::CopyAction | Qt::MoveAction, &mime, Qt::LeftButton, Qt::NoModifier);
            QApplication::sendEvent(list->viewport(), &enter);
            QDragMoveEvent move(QPoint(400, 200), Qt::CopyAction | Qt::MoveAction, &mime, Qt::LeftButton, Qt::NoModifier);
            QApplication::sendEvent(list->viewport(), &move);
            QDropEvent drop(QPointF(400, 200), Qt::CopyAction | Qt::MoveAction, &mime, Qt::LeftButton, Qt::NoModifier);
            QApplication::sendEvent(list->viewport(), &drop);
            require(drop.isAccepted(), "cross-output native drop rejected");
            until([&] { return contains(target, QStringLiteral("alpha.txt")) && appearances(QStringLiteral("alpha.txt")) == 1; }, "cross-output drop failed");
            QFile actual(path);
            require(actual.open(QIODevice::ReadOnly) && actual.readAll() == QByteArray("synthetic alpha\n"), "drag altered source file");
            require(QDir(qEnvironmentVariable("HOME") + QStringLiteral("/Desktop")).entryList(QDir::Files).size() == 3, "drag copied or removed file");
            std::cout << "PASS native drag event changes placement without file copy/deletion\n";

            auto configure = [&](bool on) {
                QProcess process;
                process.start(QStringLiteral("/usr/bin/wlr-randr"), {QStringLiteral("--output"), target, on ? QStringLiteral("--on") : QStringLiteral("--off")});
                require(process.waitForFinished(4000) && process.exitCode() == 0, "synthetic output control failed");
            };
            configure(false);
            until([&] { return desktops().size() == 2 && contains(app.primaryScreen()->name(), QStringLiteral("alpha.txt")) && appearances(QStringLiteral("alpha.txt")) == 1; }, "disconnect fallback failed");
            configure(true);
            until([&] { return desktops().size() == 3 && contains(target, QStringLiteral("alpha.txt")) && appearances(QStringLiteral("alpha.txt")) == 1; }, "reconnect restoration failed");
            require(app.desktopOutputLayout().owner(QStringLiteral("alpha.txt"), names, primary) == target, "fallback overwrote saved owner");
            std::cout << "PASS actual output removal/reconnection with one accessible icon and restored owner\n";
            const auto addedPath = qEnvironmentVariable("HOME") + QStringLiteral("/Desktop/delta.txt");
            QFile added(addedPath);
            require(added.open(QIODevice::WriteOnly), "synthetic live icon creation failed");
            added.write("synthetic live icon");
            added.close();
            until([&] { return appearances(QStringLiteral("delta.txt")) == 1; }, "live new Desktop entry not observed");
            require(added.remove(), "synthetic live icon cleanup failed");
            until([&] { return appearances(QStringLiteral("delta.txt")) == 0; }, "live deleted Desktop entry remains visible");
            std::cout << "PASS live local folder changes still update desktop models\n";
            app.exit(0);
        }
        catch(const std::exception& error) {
            std::cerr << "FAIL " << error.what() << '\n';
            app.exit(1);
        }
    });
    return app.exec();
}
