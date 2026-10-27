use tauri::{
    menu::{Menu, MenuItem},
    tray::{TrayIcon, TrayIconBuilder},
    AppHandle, Manager,
};

pub fn setup_tray(app: &AppHandle) -> Result<TrayIcon, tauri::Error> {
    let status_item = MenuItem::with_id(app, "status", "Locksmith: Control Plane Active", false, None::<&str>)?;
    let sep1 = tauri::menu::PredefinedMenuItem::separator(app)?;

    let leases_item = MenuItem::with_id(app, "leases", "🔐 Ephemeral Token Exchange (ETX)", false, None::<&str>)?;
    let sep2 = tauri::menu::PredefinedMenuItem::separator(app)?;

    let show_item = MenuItem::with_id(app, "show", "Show Locksmith Cockpit", true, None::<&str>)?;
    let quit_item = MenuItem::with_id(app, "quit", "Quit Cockpit", true, None::<&str>)?;

    let menu = Menu::with_items(
        app,
        &[
            &status_item,
            &sep1,
            &leases_item,
            &sep2,
            &show_item,
            &quit_item,
        ],
    )?;

    let mut builder = TrayIconBuilder::new()
        .menu(&menu)
        .show_menu_on_left_click(true);

    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }

    builder
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "quit" => {
                app.exit(0);
            }
            _ => {}
        })
        .build(app)
}
