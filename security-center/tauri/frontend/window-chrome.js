/* Persistent window chrome, independent of route refresh and security state. */
(() => {
  const bar = document.querySelector("#window-titlebar");
  const edges = document.querySelector("#window-resize-edges");
  const t = (key) => window.GREYWARD_I18N?.t(key) || key;
  const invoke = (action, edge = null) => window.__TAURI_INTERNALS__.invoke("window_chrome", {action, edge});
  let maximized = false;
  const control = (action, asset, label) => `<button type="button" class="window-control" data-window-action="${action}" data-window-asset="${asset}" aria-label="${t(label)}" title="${t(label)}"><img src="./assets/window-controls/${asset}-active.svg" alt="" draggable="false"><img class="window-control-hover" src="./assets/window-controls/${asset}_hover-active.svg" alt="" draggable="false"></button>`;
  bar.innerHTML = `<div class="window-drag-area"></div><div class="window-controls" role="group" aria-label="${t("window.controls")}">${control("minimize", "iconify", "window.minimize")}${control("toggleMaximize", "max", "window.maximize")}${control("close", "close", "window.close")}</div><span class="sr-only" role="status" aria-live="polite" data-window-feedback></span>`;
  edges.innerHTML = ["North", "NorthEast", "East", "SouthEast", "South", "SouthWest", "West", "NorthWest"].map(edge => `<div class="window-resize-edge" data-window-edge="${edge}"></div>`).join("");
  function update(state) {
    maximized = state.maximized;
    document.body.dataset.windowMaximized = String(maximized);
    focused(state.focused);
    const button = bar.querySelector('[data-window-action="toggleMaximize"]');
    button.title = button.ariaLabel = t(maximized ? "window.restore" : "window.maximize");
  }
  function focused(value) {
    document.body.dataset.windowFocused = String(value);
    bar.querySelectorAll("[data-window-action]").forEach(button => button.querySelectorAll("img").forEach((img, index) => {
      img.src = `./assets/window-controls/${button.dataset.windowAsset}${index ? "_hover" : ""}-${value ? "active" : "inactive"}.svg`;
    }));
  }
  async function act(action, edge) {
    try { update(await invoke(action, edge)); }
    catch { bar.querySelector("[data-window-feedback]").textContent = t("window.failed"); }
  }
  bar.querySelectorAll("[data-window-action]").forEach(button => button.addEventListener("click", () => act(button.dataset.windowAction)));
  const dragArea = bar.querySelector(".window-drag-area");
  dragArea.addEventListener("mousedown", event => {
    if (event.button === 0) { event.preventDefault(); act(event.detail === 2 ? "toggleMaximize" : "drag"); }
  });
  edges.querySelectorAll("[data-window-edge]").forEach(edge => edge.addEventListener("mousedown", event => {
    if (event.button === 0 && !maximized) { event.preventDefault(); act("resize", edge.dataset.windowEdge); }
  }));
  window.addEventListener("resize", () => act("getState"));
  window.__TAURI__?.event.listen("tauri://focus", event => focused(event.payload));
  act("getState");
})();
