pragma ComponentBehavior: Bound

import QtQuick
import Quickshell
import qs.Common
import qs.DCommon.Widgets
import qs.Modules.Settings.Widgets

Item {
    id: root
    property string managedPage: ""
    property var parentModal: null
    readonly property bool isUpdates: managedPage === "updater"
    readonly property bool isAccounts: managedPage === "users" || managedPage === "user_create"

    SettingsPage {
        SettingsCard {
            title: root.isUpdates ? I18n.tr("GREYWARD updates") : root.isAccounts ? I18n.tr("Protected accounts") : I18n.tr("Protected sign-in")
            settingKey: "greywardManagedSettings"
            tags: ["security", "authentication", "accounts", "updates", "greyward"]

            SettingsRow {
                title: root.isUpdates ? I18n.tr("Reviewed system transactions") : I18n.tr("Managed by GREYWARD")
                subtitle: root.isUpdates
                    ? I18n.tr("Review packages, compatibility and recovery in Update Center.")
                    : root.isAccounts
                        ? I18n.tr("Accounts require GREYWARD enrollment to receive their protected desktop. Generic user creation and group changes are unavailable here.")
                        : I18n.tr("The login and lock screens use GREYWARD's protected authentication runtime. Ordinary shell settings cannot change PAM, password input or its trusted surfaces.")
                iconName: "shield_lock"
            }

            SettingsRow {
                title: root.isUpdates ? I18n.tr("Update Center") : I18n.tr("Security Center")
                subtitle: root.isUpdates ? I18n.tr("Open the existing update workflow.") : I18n.tr("Inspect protection and enrolled-session status.")
                DButton {
                    text: I18n.tr("Open")
                    iconName: "open_in_new"
                    onClicked: Quickshell.execDetached(["/usr/bin/greyward-security-center-route", root.isUpdates ? "updates" : "overview"])
                }
            }
        }
        SettingsCard {
            visible: !root.isUpdates && !root.isAccounts
            title: I18n.tr("Appearance")
            SettingsRow {
                title: I18n.tr("Protected appearance controls are pending validation")
                subtitle: I18n.tr("Wallpaper, colors, typography, taskbar and dock options remain available for your ordinary desktop. This candidate does not yet offer edits to protected sign-in screens.")
            }
        }
    }
}
