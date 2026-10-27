use crate::ipc_client::{ActiveLeaseItem, DaemonStatus, LeaseResponse, LocksmithClient, RevokeResponse};
use serde::{Deserialize, Serialize};

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
}
