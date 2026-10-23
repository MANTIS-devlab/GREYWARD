#include <QApplication>
#include <QFont>
#include <QIcon>
#include <QMenu>
#include <QPainter>
#include <QProxyStyle>
#include <QStyleFactory>
#include <QStyleOptionMenuItem>
#include <QStylePlugin>
#include "palette.h"

// Selected only by the desktop-icons launcher; never a global Qt theme.
class Obsidian final : public QProxyStyle {
public:
    Obsidian() : QProxyStyle(QStyleFactory::create("Fusion")) {
        // This plugin is selected only by our desktop process. Set the native
        // theme before PCManFM snapshots QIcon::themeName in its settings.
        QIcon::setThemeName(QStringLiteral("Greyward"));
    }

    QPalette standardPalette() const override {
        const auto &c = GreywardPalette::dark;
        QPalette p = QProxyStyle::standardPalette();
        p.setColor(QPalette::Window, QColor(c.surface));
        p.setColor(QPalette::Base, QColor(c.deep));
        p.setColor(QPalette::AlternateBase, QColor(c.soft));
        p.setColor(QPalette::Button, QColor(c.raised));
        p.setColor(QPalette::WindowText, QColor(c.text));
        p.setColor(QPalette::Text, QColor(c.text));
        p.setColor(QPalette::ButtonText, QColor(c.text));
        p.setColor(QPalette::Highlight, QColor(c.raised));
        p.setColor(QPalette::HighlightedText, QColor(c.text));
        p.setColor(QPalette::Disabled, QPalette::Text, QColor(c.subtle));
        p.setColor(QPalette::Disabled, QPalette::WindowText, QColor(c.subtle));
        return p;
    }

    void polish(QPalette &p) override { p = standardPalette(); }
    void polish(QApplication *app) override {
        QProxyStyle::polish(app);
        app->setAttribute(Qt::AA_DontShowIconsInMenus, true);
        app->setFont(QFont("Inter", 10));
    }
    void polish(QWidget *widget) override {
        QProxyStyle::polish(widget);
        if (qobject_cast<QMenu *>(widget)) {
            widget->setAttribute(Qt::WA_TranslucentBackground);
            widget->setAutoFillBackground(false);
        }
    }

    void drawPrimitive(PrimitiveElement e, const QStyleOption *o,
                       QPainter *p, const QWidget *w = nullptr) const override {
        if (e == PE_PanelMenu) {
            p->save();
            p->setRenderHint(QPainter::Antialiasing);
            QColor border(GreywardPalette::dark.border); border.setAlpha(180);
            QColor surface(GreywardPalette::dark.surface); surface.setAlpha(248);
            p->setPen(border);
            p->setBrush(surface);
            p->drawRoundedRect(QRectF(o->rect).adjusted(.5, .5, -.5, -.5), 7, 7);
            p->restore();
            return;
        }
        QProxyStyle::drawPrimitive(e, o, p, w);
    }
    void drawControl(ControlElement e, const QStyleOption *o,
                     QPainter *p, const QWidget *w = nullptr) const override {
        if (e == CE_MenuItem) {
            if (const auto *item = qstyleoption_cast<const QStyleOptionMenuItem *>(o)) {
                QStyleOptionMenuItem clean(*item);
                clean.icon = QIcon();
                clean.maxIconWidth = 0;
                clean.palette = standardPalette();
                QProxyStyle::drawControl(e, &clean, p, w);
                return;
            }
        }
        QProxyStyle::drawControl(e, o, p, w);
    }
    QSize sizeFromContents(ContentsType t, const QStyleOption *o, const QSize &s,
                           const QWidget *w) const override {
        QSize result = QProxyStyle::sizeFromContents(t, o, s, w);
        if (t == CT_MenuItem) {
            const auto *item = qstyleoption_cast<const QStyleOptionMenuItem *>(o);
            if (item && item->menuItemType != QStyleOptionMenuItem::Separator)
                result.setHeight(qMax(result.height(), 30));
            result.rwidth() += 14;
        }
        return result;
    }
};

class ObsidianPlugin final : public QStylePlugin {
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "org.qt-project.Qt.QStyleFactoryInterface" FILE "obsidian.json")
public:
    QStyle *create(const QString &key) override {
        return key.compare("GreywardDesktop", Qt::CaseInsensitive) == 0
            ? new Obsidian : nullptr;
    }
};
#include "obsidian.moc"
