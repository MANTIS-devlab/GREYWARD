// Bundled startup instrumentation; no inline scripting or backend authority.
(() => {
  const marks = window.__greywardStartupMarks = [];
  const mark = (name) => marks.push({name, ms: Math.round(performance.now() * 100) / 100});
  const markOnce = (name) => {
    if (!marks.some((entry) => entry.name === name)) mark(name);
  };
  window.__greywardStartupMark = mark;
  window.__greywardStartupMarkOnce = markOnce;
  mark("document_script_start");
  document.addEventListener("DOMContentLoaded", () => markOnce("dom_content_loaded"), {once: true});
  window.addEventListener("load", () => markOnce("window_load"), {once: true});
})();
