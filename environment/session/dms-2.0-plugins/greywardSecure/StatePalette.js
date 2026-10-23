.pragma library
// Generated from branding/source/greyward-desktop-palette.json; do not edit colors here.
var modes = {
  "dark": {
    "positive": "#A5DBB7",
    "warning": "#EDCA85",
    "error": "#F4A59B"
  },
  "light": {
    "positive": "#2E6B53",
    "warning": "#7A5B23",
    "error": "#9C4851"
  }
};
function color(tone, light) {
    return modes[light ? "light" : "dark"][tone === "positive" ? "positive" : tone === "critical" ? "error" : "warning"];
}
