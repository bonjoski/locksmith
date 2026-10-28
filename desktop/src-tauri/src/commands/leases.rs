use crate::ipc_client::{ActiveLeaseItem, DaemonStatus, LeaseResponse, LocksmithClient, RevokeResponse};
use super::binary::find_locksmith_binary;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[tauri::command]
pub async fn check_daemon_status() -> Result<DaemonStatus, String> {
    let client = LocksmithClient::new();
    let socket_path = client.socket_path.to_string_lossy().to_string();
    
    if !client.is_alive() {
        return Ok(DaemonStatus {
            online: false,
            socket_path,
            version: "unknown".to_string(),
            active_leases_count: 0,
        });
    }

    match client.ping().await {
        Ok(status) => {
            let leases = client.list_leases().await.unwrap_or_default();
            Ok(DaemonStatus {
                online: status == "PONG",
                socket_path,
                version: "1.0".to_string(),
                active_leases_count: leases.len(),
            })
        }
        Err(_) => Ok(DaemonStatus {
            online: false,
            socket_path,
            version: "unreachable".to_string(),
            active_leases_count: 0,
        }),
    }
}

#[tauri::command]
pub async fn list_active_leases() -> Result<Vec<ActiveLeaseItem>, String> {
    let client = LocksmithClient::new();
    if !client.is_alive() {
        return Ok(vec![]);
    }
    client.list_leases().await
}

#[tauri::command]
pub async fn revoke_active_lease(lease_id: String) -> Result<RevokeResponse, String> {
    let client = LocksmithClient::new();
    client.revoke_lease(&lease_id).await
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLeaseArgs {
    pub secret_name: String,
    pub ttl_secs: u64,
    pub max_uses: i32,
}

#[tauri::command]
pub async fn request_ephemeral_lease(args: RequestLeaseArgs) -> Result<LeaseResponse, String> {
    let client = LocksmithClient::new();
    client
        .request_lease(&args.secret_name, args.ttl_secs, args.max_uses)
        .await
}

fn get_pid_file_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".locksmith").join("locksmith.pid")
    } else {
        PathBuf::from("/tmp/locksmith.pid")
    }
}

fn get_daemon_log_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".locksmith").join("daemon.log")
    } else {
        PathBuf::from("/tmp/locksmith_daemon.log")
    }
}

pub fn parse_and_validate_daemon_pid(raw: &str) -> Option<i32> {
    let trimmed = raw.trim();
    if let Ok(pid) = trimmed.parse::<i32>() {
        let current_pid = std::process::id() as i32;
        // Guard against PID 0 (entire process group), PID 1 (init/launchd),
        // negative PIDs (arbitrary process groups), and self-termination
        if pid > 1 && pid != current_pid && pid <= 4_194_304 {
            return Some(pid);
        }
    }
    None
}

fn safe_remove_or_unlink(path: &PathBuf) {
    if path.is_symlink() || path.exists() {
        let _ = std::fs::remove_file(path);
    }
}

async fn terminate_existing_daemon() {
    let pid_path = get_pid_file_path();
    if !pid_path.is_symlink() {
        if let Ok(content) = std::fs::read_to_string(&pid_path) {
            if let Some(pid) = parse_and_validate_daemon_pid(&content) {
                #[cfg(unix)]
                unsafe { // SAFETY: libc::kill is a standard POSIX system call with zero memory side effects. Target PID is verified > 1, positive, below max PID limits, and not self.
                    libc::kill(pid, libc::SIGTERM);
                }
                #[cfg(windows)]
                {
                    let _ = std::process::Command::new("taskkill")
                        .args(&["/F", "/PID", &pid.to_string()])
                        .output();
                }
            }
        }
    }

    #[cfg(unix)]
    {
        // Also terminate any daemon process by pattern to clean stale runs
        let _ = std::process::Command::new("pkill")
            .args(&["-f", "locksmith daemon"])
            .output();
    }

    // Give process brief moment to release socket
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

    safe_remove_or_unlink(&pid_path);
}

#[tauri::command]
pub async fn restart_daemon() -> Result<DaemonStatus, String> {
    let client = LocksmithClient::new();
    let socket_path = client.socket_path.clone();

    // 1. Terminate existing daemon
    terminate_existing_daemon().await;

    // 2. Remove stale socket files if any
    #[cfg(not(target_os = "windows"))]
    {
        safe_remove_or_unlink(&socket_path);
        if let Ok(home) = std::env::var("HOME") {
            let dir = PathBuf::from(home).join(".locksmith");
            safe_remove_or_unlink(&dir.join("locksmith.sock"));
            safe_remove_or_unlink(&dir.join("locksmithd.sock"));
        }
    }

    // 3. Find locksmith binary
    let bin = find_locksmith_binary();

    // 4. Ensure socket parent directory exists
    if let Some(parent) = socket_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // 5. Spawn new daemon process detached
    let log_path = get_daemon_log_path();
    let mut cmd = std::process::Command::new(&bin);
    cmd.arg("daemon");
    cmd.stdin(std::process::Stdio::null());

    if let Ok(log_file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        if let Ok(err_clone) = log_file.try_clone() {
            cmd.stdout(log_file);
            cmd.stderr(err_clone);
        }
    }

    let child = cmd.spawn()
        .map_err(|e| format!("Failed to spawn locksmith daemon at {:?}: {}", bin, e))?;

    let new_pid = child.id();
    let pid_path = get_pid_file_path();
    safe_remove_or_unlink(&pid_path);
    let _ = std::fs::write(&pid_path, format!("{}", new_pid));

    // 6. Poll for readiness (up to 4 seconds)
    for _ in 0..20 {
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        if let Ok(status) = client.ping().await {
            if status == "PONG" {
                let leases = client.list_leases().await.unwrap_or_default();
                return Ok(DaemonStatus {
                    online: true,
                    socket_path: socket_path.to_string_lossy().to_string(),
                    version: "1.0".to_string(),
                    active_leases_count: leases.len(),
                });
            }
        }
    }

    Err("Daemon started but IPC socket did not become ready within timeout".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_lease_args_serde() {
        let args = RequestLeaseArgs {
            secret_name: "gitlab/glab/token".to_string(),
            ttl_secs: 600,
            max_uses: 10,
        };

        let json = serde_json::to_string(&args).expect("serialize failed");
        let parsed: RequestLeaseArgs = serde_json::from_str(&json).expect("deserialize failed");

        assert_eq!(parsed.secret_name, "gitlab/glab/token");
        assert_eq!(parsed.ttl_secs, 600);
        assert_eq!(parsed.max_uses, 10);
    }

    #[test]
    fn test_daemon_status_serde() {
        let status = DaemonStatus {
            online: true,
            socket_path: "/tmp/locksmith.sock".to_string(),
            version: "1.0".to_string(),
            active_leases_count: 3,
        };

        let json = serde_json::to_string(&status).expect("serialize failed");
        let parsed: DaemonStatus = serde_json::from_str(&json).expect("deserialize failed");

        assert!(parsed.online);
        assert_eq!(parsed.active_leases_count, 3);
        assert_eq!(parsed.version, "1.0");
    }

    #[test]
    fn test_adversarial_daemon_pid_validation() {
        // PID 0 (all processes in current group) must be rejected
        assert_eq!(parse_and_validate_daemon_pid("0"), None);
        // PID 1 (init / launchd) must be rejected
        assert_eq!(parse_and_validate_daemon_pid("1"), None);
        // Negative PID (arbitrary process group kill) must be rejected
        assert_eq!(parse_and_validate_daemon_pid("-1"), None);
        assert_eq!(parse_and_validate_daemon_pid("-42"), None);
        // Self PID must be rejected
        let current_pid = std::process::id() as i32;
        assert_eq!(parse_and_validate_daemon_pid(&current_pid.to_string()), None);
        // Non-numeric garbage must be rejected
        assert_eq!(parse_and_validate_daemon_pid("garbage_pid"), None);
        assert_eq!(parse_and_validate_daemon_pid("123; rm -rf /"), None);
        assert_eq!(parse_and_validate_daemon_pid("999999999999999999"), None);
        // Excessive PID above system max must be rejected
        assert_eq!(parse_and_validate_daemon_pid("9999999"), None);
        // Valid pid must be accepted
        assert_eq!(parse_and_validate_daemon_pid("45678"), Some(45678));
    }

    #[tokio::test]
    async fn test_restart_daemon_live() {
        let res = restart_daemon().await;
        assert!(res.is_ok(), "restart_daemon failed: {:?}", res.err());
        let status = res.unwrap();
        assert!(status.online);
        assert_eq!(status.version, "1.0");
    }
}
