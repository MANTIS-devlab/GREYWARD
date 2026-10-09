use serde::{Deserialize, Serialize};
use tauri::WebviewWindow;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WindowAction {
    GetState,
    Drag,
    Resize,
    Minimize,
    ToggleMaximize,
    Close,
}

#[derive(Deserialize)]
pub enum ResizeEdge {
    North,
    NorthEast,
    East,
    SouthEast,
    South,
    SouthWest,
    West,
    NorthWest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowState {
    maximized: bool,
    focused: bool,
}

#[tauri::command]
pub fn window_chrome(
    window: WebviewWindow,
    action: WindowAction,
    edge: Option<ResizeEdge>,
) -> Result<WindowState, String> {
    if window.label() != "main" {
        return Err("Window controls are only available to the main window.".into());
    }
    let result = match action {
        WindowAction::GetState => Ok(()),
        WindowAction::Drag => window.start_dragging(),
        WindowAction::Resize => {
            #[cfg(target_os = "linux")]
            {
                use gtk::{gdk::WindowEdge as ResizeDirection, prelude::GtkWindowExt};
                let direction = match edge.ok_or("A resize edge is required.")? {
                    ResizeEdge::North => ResizeDirection::North,
                    ResizeEdge::NorthEast => ResizeDirection::NorthEast,
                    ResizeEdge::East => ResizeDirection::East,
                    ResizeEdge::SouthEast => ResizeDirection::SouthEast,
                    ResizeEdge::South => ResizeDirection::South,
                    ResizeEdge::SouthWest => ResizeDirection::SouthWest,
                    ResizeEdge::West => ResizeDirection::West,
                    ResizeEdge::NorthWest => ResizeDirection::NorthWest,
                };
                let native = window.gtk_window().map_err(|error| error.to_string())?;
                // Match Tao's native Wayland move handoff: GDK uses the current
                // seat button serial; global coordinates do not exist on Wayland.
                native.begin_resize_drag(direction, 1, 0, 0, 0);
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            return Err("Resize dragging requires the GREYWARD GTK desktop.".into());
        }
        WindowAction::Minimize => window.minimize(),
        WindowAction::ToggleMaximize => {
            if window.is_maximized().map_err(|error| error.to_string())? {
                window.unmaximize()
            } else {
                window.maximize()
            }
        }
        WindowAction::Close => window.close(),
    };
    result.map_err(|error| error.to_string())?;
    Ok(WindowState {
        maximized: window.is_maximized().map_err(|error| error.to_string())?,
        focused: window.is_focused().map_err(|error| error.to_string())?,
    })
}
