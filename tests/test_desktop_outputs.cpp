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
#include <QJsonDocument>
#include <QJsonObject>
#include <QListView>
#include <QMimeData>
#include <QProcess>
#include <QThread>
#include <QTimer>
#include <LayerShellQt/window.h>
#include "application.h"
#include "desktopwindow.h"
#include "launcher.h"
#include <functional>
#include <iostream>
#include <stdexcept>

// Interpose only the static detached launch in this linked synthetic driver.
// No installed Strata process or host application bus is contacted.
static QString detachedProgram;
static QStringList detachedArguments;
static int detachedLaunches = 0;
static bool detachedSucceeds = true;
bool QProcess::startDetached(const QString& program, const QStringList& arguments,
                             const QString&, qint64*) {
    detachedProgram = program;
    detachedArguments = arguments;
    ++detachedLaunches;
    return detachedSucceeds;
}

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

static QPoint position(const QString& screen, const QString& file) {
    auto window = desktops().value(screen);
    if(!window) return QPoint(-1, -1);
    auto list = window->findChild<QListView*>();
    if(!list || !list->model()) return QPoint(-1, -1);
    for(int i = 0; i < list->model()->rowCount(); ++i) {
        auto index = list->model()->index(i, 0);
        if(index.data(Qt::DisplayRole).toString() == file) return list->visualRect(index).topLeft();
    }
    return QPoint(-1, -1);
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
            const auto profilePath = qEnvironmentVariable("XDG_CONFIG_HOME") + QStringLiteral("/pcmanfm-qt/greyward-test");
            QFile stateFile(profilePath + QStringLiteral("/cycle-state.json"));
            if(stateFile.exists()) {
                require(stateFile.open(QIODevice::ReadOnly), "saved process-restart proof unavailable");
                const auto state = QJsonDocument::fromJson(stateFile.readAll()).object();
                const auto restoredOutput = state.value(QStringLiteral("output")).toString();
                const QPoint restoredPoint(state.value(QStringLiteral("x")).toInt(), state.value(QStringLiteral("y")).toInt());
                require(names.contains(restoredOutput), "saved output unavailable in restarted process");
                until([&] { return position(restoredOutput, QStringLiteral("alpha.txt")) == restoredPoint; }, "fresh process did not restore exact icon coordinates");
                require(appearances(QStringLiteral("alpha.txt")) == 1, "fresh process duplicated the icon");
                std::cout << "PASS fresh application process restores saved output and exact coordinates\n";
                app.exit(0);
                return;
            }
            until([&] { return contains(primary, QStringLiteral("alpha.txt")) && appearances(QStringLiteral("alpha.txt")) == 1; }, "initial icon duplicated or absent");
            for(auto window : desktops()) {
                require(window->getDesktopScreen() != nullptr, "output binding absent");
                require(LayerShellQt::Window::get(window->windowHandle())->layer() == LayerShellQt::Window::LayerBottom, "icons share wallpaper layer");
            }
            const QString folder = qEnvironmentVariable("HOME") + QStringLiteral("/Desktop/folder ; $(literal)");
            const QString expectedUri = QUrl::fromLocalFile(folder).toString(QUrl::FullyEncoded);
            app.launchFiles(qEnvironmentVariable("HOME") + QStringLiteral("/Desktop"),
                            {QStringLiteral("folder ; $(literal)"), QStringLiteral("--looks-like-option")}, false, false);
            require(detachedProgram == QStringLiteral("/usr/bin/strata"), "folder IPC did not select Strata");
            require(detachedArguments.size() == 2 && detachedArguments.first() == expectedUri
                    && detachedArguments.last().startsWith(QStringLiteral("file:///")), "folder operands were not literal encoded URIs");
            const int beforeEmpty = detachedLaunches;
            app.launchFiles(QDir::homePath(), {}, false, false);
            require(detachedLaunches == beforeEmpty, "empty IPC unexpectedly launched an application");
            Fm::FilePathList folders;
            folders.push_back(Fm::FilePath::fromLocalPath(folder.toUtf8().constData()));
            PCManFM::Launcher().launchPaths(nullptr, folders);
            until([&] { return detachedLaunches == beforeEmpty + 1; }, "native folder launcher did not reach Strata");
            // GIO encodes the semicolon as %3B; Qt leaves the legal URI path
            // character literal. Both must address the exact synthetic folder.
            const QUrl routedFolder(detachedArguments.value(0), QUrl::StrictMode);
            require(detachedProgram == QStringLiteral("/usr/bin/strata") && detachedArguments.size() == 1
                    && routedFolder.isValid() && routedFolder.isLocalFile() && routedFolder.toLocalFile() == folder
                    && !detachedArguments.first().contains(QLatin1Char(' ')), "desktop folder bypassed literal Strata routing");
            detachedSucceeds = false;
            app.launchFiles(QDir::homePath(), {folder}, false, false);
            detachedSucceeds = true;
            for (auto widget : QApplication::topLevelWidgets())
                require(!widget->inherits("PCManFM::MainWindow"), "a second file browser opened");
            require(desktops().size() == 3, "failed Strata launch closed the desktop");
            std::cout << "PASS native folder and IPC routing selects Strata with literal URIs, empty/failure preserve the desktop\n";

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
            until([&] { return position(target, QStringLiteral("alpha.txt")).x() > 200; }, "placed icon was not restored to its custom cell");
            const auto placed = position(target, QStringLiteral("alpha.txt"));
            const auto profile = qEnvironmentVariable("XDG_CONFIG_HOME") + QStringLiteral("/pcmanfm-qt/greyward-test");
            const auto tripleFile = Greyward::DesktopOutputLayout::positionFile(profile, target, names);
            require(QFile::exists(tripleFile), "manual placement was not persisted immediately");
            QSettings saved(tripleFile, QSettings::IniFormat);
            const auto savedPoint = saved.value(QStringLiteral("alpha.txt/pos")).toPoint();
            auto configureOutput = [&](const QString& output, bool on) {
                QProcess process;
                process.start(QStringLiteral("/usr/bin/wlr-randr"), {QStringLiteral("--output"), output, on ? QStringLiteral("--on") : QStringLiteral("--off")});
                require(process.waitForFinished(4000) && process.exitCode() == 0, "output configuration failed");
            };
            for(int cycle = 0; cycle < 2; ++cycle) {
                configureOutput(target, false);
                configureOutput(external, false);
                until([&] { return desktops().size() == 1 && appearances(QStringLiteral("alpha.txt")) == 1
                    && position(primary, QStringLiteral("alpha.txt")).x() > 0
                    && position(primary, QStringLiteral("alpha.txt")).y() > 0; }, "single-output fallback layout failed");
                auto singleList = desktops().value(primary)->findChild<QListView*>();
                for(int row = 0; row < singleList->model()->rowCount(); ++row) {
                    auto index = singleList->model()->index(row, 0);
                    if(index.data(Qt::DisplayRole).toString() == QStringLiteral("beta.txt")) {
                        singleList->selectionModel()->select(index, QItemSelectionModel::ClearAndSelect);
                        require(QMetaObject::invokeMethod(desktops().value(primary), "onStickToCurrentPos", Qt::DirectConnection,
                            Q_ARG(bool, true)), "single-output manual placement could not be saved");
                    }
                }
                app.desktopManager(false);
                app.desktopManager(true);
                until([&] { return desktops().size() == 1 && appearances(QStringLiteral("alpha.txt")) == 1; }, "single-output desktop restart lost icons");
                const auto singleFile = Greyward::DesktopOutputLayout::positionFile(profile, primary, {primary});
                require(QFile::exists(singleFile), "destroyed output windows did not save the single-output layout");
                require(singleFile != tripleFile, "single-output coordinates alias the three-output layout");
                configureOutput(external, true);
                configureOutput(target, true);
                until([&] { return desktops().size() == 3 && position(target, QStringLiteral("alpha.txt")) == placed; }, "three-output coordinates changed after fallback/restart");
                require(appearances(QStringLiteral("alpha.txt")) == 1, "restored icon duplicated");
                app.desktopManager(false);
                app.desktopManager(true);
                until([&] { return desktops().size() == 3 && position(target, QStringLiteral("alpha.txt")) == placed; }, "three-output desktop restart lost placement");
                saved.sync();
                require(saved.value(QStringLiteral("alpha.txt/pos")).toPoint() == savedPoint, "fallback overwrote the original saved cell");
            }
            std::cout << "PASS repeated three/one/three-output cycles, exact coordinates, window recreation and isolated layout files\n";
            const auto addedPath = qEnvironmentVariable("HOME") + QStringLiteral("/Desktop/delta.txt");
            QFile added(addedPath);
            require(added.open(QIODevice::WriteOnly), "synthetic live icon creation failed");
            added.write("synthetic live icon");
            added.close();
            until([&] { return appearances(QStringLiteral("delta.txt")) == 1; }, "live new Desktop entry not observed");
            require(added.remove(), "synthetic live icon cleanup failed");
            until([&] { return appearances(QStringLiteral("delta.txt")) == 0; }, "live deleted Desktop entry remains visible");
            std::cout << "PASS live local folder changes still update desktop models\n";
            require(stateFile.open(QIODevice::WriteOnly), "could not save process-restart proof");
            stateFile.write(QJsonDocument(QJsonObject{{QStringLiteral("output"), target},
                {QStringLiteral("x"), placed.x()}, {QStringLiteral("y"), placed.y()}}).toJson());
            stateFile.close();
            app.exit(0);
        }
        catch(const std::exception& error) {
            std::cerr << "FAIL " << error.what() << '\n';
            app.exit(1);
        }
    });
    const auto code = app.exec();
    app.desktopManager(false);
    return code;
}
