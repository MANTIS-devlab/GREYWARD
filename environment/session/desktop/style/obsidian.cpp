#include <QApplication>
#include <QFont>
#include <QMenu>
#include <QPainter>
#include <QProxyStyle>
#include <QStyleFactory>
#include <QStyleOptionMenuItem>
#include <QStylePlugin>

// Selected only by the desktop-icons launcher; never a global Qt theme.
class Obsidian final : public QProxyStyle {
public:
    Obsidian() : QProxyStyle(QStyleFactory::create("Fusion")) {}

    QPalette standardPalette() const override {
        QPalette p = QProxyStyle::standardPalette();
        p.setColor(QPalette::Window, QColor("#171a1d"));
        p.setColor(QPalette::Base, QColor("#101214"));
        p.setColor(QPalette::AlternateBase, QColor("#202529"));
        p.setColor(QPalette::Button, QColor("#242a2e"));
        p.setColor(QPalette::WindowText, QColor("#e2e5e7"));
        p.setColor(QPalette::Text, QColor("#e2e5e7"));
        p.setColor(QPalette::ButtonText, QColor("#e2e5e7"));
        p.setColor(QPalette::Highlight, QColor("#39444b"));
        p.setColor(QPalette::HighlightedText, QColor("#f1f3f4"));
        p.setColor(QPalette::Disabled, QPalette::Text, QColor("#899399"));
        p.setColor(QPalette::Disabled, QPalette::WindowText, QColor("#899399"));
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
            p->setPen(QColor(107, 119, 127, 130));
            p->setBrush(QColor(21, 25, 28, 243));
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
