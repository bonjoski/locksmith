mod commands;
pub mod ipc_client;
mod tray;

use commands::leases::{check_daemon_status, list_active_leases, request_ephemeral_lease, revoke_active_lease};
use commands::audit::{get_audit_events, record_audit_event};
use commands::vault::{delete_vault_secret, get_vault_secrets, reveal_secret_biometric};
use commands::rotation::{get_access_control, get_rotation_rules, trigger_secret_rotation, update_access_control};

#[cfg(target_os = "macos")]
extern "C" {
    fn locksmith_set_dock_icon(bytes: *const u8, len: usize);
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            #[cfg(target_os = "macos")]
            unsafe { // SAFETY: ICON_BYTES is valid for program lifetime and Cocoa image conversion is memory safe
                const ICON_BYTES: &[u8] = include_bytes!("../icons/icon.png");
                locksmith_set_dock_icon(ICON_BYTES.as_ptr(), ICON_BYTES.len());
            }

            #[cfg(desktop)]
            {
                let _ = tray::setup_tray(app.handle());
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            check_daemon_status,
            list_active_leases,
            revoke_active_lease,
            request_ephemeral_lease,
            get_audit_events,
            record_audit_event,
            get_vault_secrets,
            reveal_secret_biometric,
            delete_vault_secret,
            get_rotation_rules,
            trigger_secret_rotation,
            get_access_control,
            update_access_control
        ])
        .run(tauri::generate_context!())
        .expect("error while running locksmith desktop application");
}
