"""Source contracts for the GREYWARD multi-display greeter."""
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "environment/production/dms-greeter-ui"


class DmsGreeterSource(unittest.TestCase):
    def test_single_user_wrong_name_can_return_to_editable_username_entry(self):
        content = (UI / "Modules/Greetd/GreeterContent.qml").read_text()
        recovery = content.split("function returnToUserPicker() {", 1)[1].split("function selectUser", 1)[0]
        self.assertNotIn("if (!root.pickerAvailable)\n            return;", recovery)
        self.assertIn("root.manualUsernameEntry = true;", recovery)
        self.assertIn("Qt.callLater(() => inputField.forceActiveFocus());", recovery)
        self.assertIn('I18n.tr("Change username")', content)
        self.assertIn("activeFocusOnTab: true", content)
        self.assertIn("Accessible.role: Accessible.Button", content)

    def test_greeter_creates_one_surface_for_each_wayland_screen(self):
        surface = (UI / "Modules/Greetd/GreeterSurface.qml").read_text()
        self.assertIn("Variants {", surface)
        self.assertIn("model: Quickshell.screens", surface)
        self.assertIn("screen: modelData", surface)
        self.assertIn("GreeterContent {", surface)

    def test_session_metrics_use_nonvisual_instantiator_delegate(self):
        content = (UI / "Modules/Greetd/GreeterContent.qml").read_text()
        self.assertIn("Instantiator {\n                id: sessionMetricsInstantiator", content)
        self.assertIn("sessionMetricsInstantiator.objectAt(i)", content)
        self.assertNotIn("sessionMetricsRepeater", content)

    def test_physical_greeter_uses_validated_gles_renderer_even_with_old_overrides(self):
        wrapper = (ROOT / "environment/production/greyward-start-dms-greeter").read_text()
        self.assertIn('if [ "$software_renderer" = true ]; then', wrapper)
        self.assertIn("export WLR_RENDERER=pixman", wrapper)
        self.assertIn("export WLR_RENDERER=gles2", wrapper)
        self.assertIn("export WLR_NO_HARDWARE_CURSORS=1", wrapper)
        self.assertIn("export WLR_DRM_NO_MODIFIERS=1", wrapper)
        self.assertIn("else\n  # Match the renderer", wrapper)
        for variable in ("WLR_RENDERER_ALLOW_SOFTWARE", "LIBGL_ALWAYS_SOFTWARE",
                         "QT_QUICK_BACKEND", "QSG_RHI_BACKEND", "QT_OPENGL"):
            self.assertIn(variable, wrapper.split("else", 1)[1])
        self.assertIn('exec /usr/bin/dms-greeter "$@"', wrapper)

    def test_production_installs_and_selects_the_reviewed_external_ui(self):
        provision = (ROOT / "environment/production/provision.sh").read_text()
        builder = (ROOT / "environment/image/build.sh").read_text()
        acceptance = (ROOT / "environment/production/production-acceptance.sh").read_text()
        self.assertIn("$production/dms-greeter-ui/shell.qml", builder)
        self.assertIn('cp -a "$production/dms-greeter-ui" "$output/dms-greeter-ui"', builder)
        self.assertIn("--shell-dir /usr/share/greyward/dms-greeter-ui", provision)
        self.assertIn("greyward-start-dms-greeter", provision)
        self.assertIn("dms-greeter-ui", acceptance)
        self.assertIn("GREYWARD physical greeter does not select the validated GLES2 renderer", acceptance)
        self.assertIn("Change username", (UI / "Modules/Greetd/GreeterContent.qml").read_text())


if __name__ == "__main__":
    unittest.main()
