use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const PROTOCOL_VERSION: &str = "1.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseRequest {
    pub version: String,
    pub action: String,
    pub client_pid: i32,
    pub process_start_time: i64,
    pub client_binary_hash: String,
    pub secret_name: String,
    pub lease_ttl: u64, // Nanoseconds
    pub max_uses: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_ticket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spiffe_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseResponse {
    pub status: String,
    #[serde(default)]
    pub lease_id: Option<String>,
    #[serde(default)]
    pub secret_value: Option<Vec<u8>>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub session_ticket: Option<String>,
    #[serde(default)]
    pub spiffe_id: Option<String>,
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeRequest {
    pub version: String,
    pub action: String,
    pub lease_id: String,
    pub client_pid: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeResponse {
    #[serde(default)]
    pub success: bool,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveLeaseItem {
    pub lease_id: String,
    pub secret_name: String,
    pub client_pid: i32,
    pub process_start_time: i64,
    pub client_binary_hash: String,
    #[serde(default)]
    pub spiffe_id: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    pub max_uses: i32,
    pub uses_count: i32,
    #[serde(default)]
    pub session_ticket_id: Option<String>,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListLeasesResponse {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub leases: Vec<ActiveLeaseItem>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub online: bool,
    pub socket_path: String,
    pub version: String,
    pub active_leases_count: usize,
}

pub fn default_socket_path() -> PathBuf {
    if let Ok(path) = std::env::var("LOCKSMITH_SOCKET") {
        if !path.trim().is_empty() {
            return PathBuf::from(path);
        }
    }

    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"\\.\pipe\locksmithd")
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(home) = std::env::var("HOME") {
            let primary = PathBuf::from(&home).join(".locksmith").join("locksmithd.sock");
            if primary.exists() {
                return primary;
            }
            let compat = PathBuf::from(&home).join(".locksmith").join("locksmith.sock");
            if compat.exists() {
                return compat;
            }
            primary
        } else {
            let uid = unsafe { // SAFETY: getuid is a POSIX libc query with zero memory side effects
                libc::getuid()
            };
            PathBuf::from(format!("/tmp/locksmithd-{}.sock", uid))
        }
    }
}

pub struct LocksmithClient {
    pub socket_path: PathBuf,
}

impl LocksmithClient {
    pub fn new() -> Self {
        Self {
            socket_path: default_socket_path(),
        }
    }

    pub fn with_socket(path: PathBuf) -> Self {
        Self { socket_path: path }
    }

    pub fn is_alive(&self) -> bool {
        #[cfg(not(target_os = "windows"))]
        {
            self.socket_path.exists()
        }
        #[cfg(target_os = "windows")]
        {
            true
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn send_raw(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let mut stream = tokio::net::UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| format!("Failed to connect to daemon at {:?}: {}", self.socket_path, e))?;

        stream
            .write_all(payload)
            .await
            .map_err(|e| format!("Failed to write request: {}", e))?;

        let mut buf = vec![0u8; 65536];
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        if n == 0 {
            return Err("Daemon closed connection without response".to_string());
        }

        buf.truncate(n);
        Ok(buf)
    }

    #[cfg(target_os = "windows")]
    pub async fn send_raw(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let pipe_path = self.socket_path.to_string_lossy();
        let mut client = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(&pipe_path)
            .map_err(|e| format!("Failed to open named pipe {}: {}", pipe_path, e))?;

        client
            .write_all(payload)
            .await
            .map_err(|e| format!("Failed to write request: {}", e))?;

        let mut buf = vec![0u8; 65536];
        let n = client
            .read(&mut buf)
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        if n == 0 {
            return Err("Daemon closed connection without response".to_string());
        }

        buf.truncate(n);
        Ok(buf)
    }

    pub async fn ping(&self) -> Result<String, String> {
        let req = serde_json::json!({
            "action": "ping"
        });
        let bytes = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
        let res_bytes = self.send_raw(&bytes).await?;
        let val: serde_json::Value = serde_json::from_slice(&res_bytes).map_err(|e| e.to_string())?;
        
        if let Some(status) = val.get("status").and_then(|v| v.as_str()) {
            Ok(status.to_string())
        } else {
            Err("Invalid ping response".to_string())
        }
    }

    pub async fn list_leases(&self) -> Result<Vec<ActiveLeaseItem>, String> {
        let req = serde_json::json!({
            "action": "list_leases"
        });
        let bytes = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
        let res_bytes = self.send_raw(&bytes).await?;
        let resp: ListLeasesResponse = serde_json::from_slice(&res_bytes)
            .map_err(|e| format!("Failed to parse list_leases response: {}", e))?;

        if let Some(err) = resp.error {
            return Err(err);
        }
        Ok(resp.leases)
    }

    pub async fn request_lease(
        &self,
        secret_name: &str,
        ttl_secs: u64,
        max_uses: i32,
    ) -> Result<LeaseResponse, String> {
        let pid = std::process::id() as i32;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let req = LeaseRequest {
            version: PROTOCOL_VERSION.to_string(),
            action: "request_lease".to_string(),
            client_pid: pid,
            process_start_time: now,
            client_binary_hash: "cockpit-client".to_string(),
            secret_name: secret_name.to_string(),
            lease_ttl: ttl_secs * 1_000_000_000, // convert secs to nanoseconds
            max_uses,
            session_ticket: None,
            target_command: Some("locksmith-cockpit".to_string()),
            spiffe_id: None,
        };

        let bytes = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
        let res_bytes = self.send_raw(&bytes).await?;
        let resp: LeaseResponse = serde_json::from_slice(&res_bytes)
            .map_err(|e| format!("Failed to parse lease response: {}", e))?;

        Ok(resp)
    }

    pub async fn revoke_lease(&self, lease_id: &str) -> Result<RevokeResponse, String> {
        let pid = std::process::id() as i32;
        let req = RevokeRequest {
            version: PROTOCOL_VERSION.to_string(),
            action: "revoke_lease".to_string(),
            lease_id: lease_id.to_string(),
            client_pid: pid,
        };

        let bytes = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
        let res_bytes = self.send_raw(&bytes).await?;
        let resp: RevokeResponse = serde_json::from_slice(&res_bytes)
            .map_err(|e| format!("Failed to parse revoke response: {}", e))?;

        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_socket_path() {
        let path = default_socket_path();
        let path_str = path.to_string_lossy();
        assert!(
            path_str.contains("locksmith"),
            "Expected locksmith in socket path, got: {}",
            path_str
        );
    }

    #[test]
    fn test_lease_request_serialization() {
        let req = LeaseRequest {
            version: PROTOCOL_VERSION.to_string(),
            action: "request_lease".to_string(),
            client_pid: 1234,
            process_start_time: 1700000000,
            client_binary_hash: "abc123hash".to_string(),
            secret_name: "test-secret".to_string(),
            lease_ttl: 300_000_000_000, // 300s in ns
            max_uses: 5,
            session_ticket: None,
            target_command: Some("test-cmd".to_string()),
            spiffe_id: None,
        };

        let json_str = serde_json::to_string(&req).expect("Failed to serialize");
        assert!(json_str.contains("\"version\":\"1.0\""));
        assert!(json_str.contains("\"action\":\"request_lease\""));
        assert!(json_str.contains("\"client_pid\":1234"));
        assert!(json_str.contains("\"secret_name\":\"test-secret\""));
        assert!(json_str.contains("\"lease_ttl\":300000000000"));
        assert!(json_str.contains("\"max_uses\":5"));
    }

    #[test]
    fn test_lease_response_deserialization() {
        let json_data = r#"{
            "status": "GRANTED",
            "lease_id": "ls-lease-test-123",
            "expires_at": "2026-10-25T15:00:00Z",
            "ttl_seconds": 300
        }"#;

        let resp: LeaseResponse = serde_json::from_str(json_data).expect("Failed to deserialize");
        assert_eq!(resp.status, "GRANTED");
        assert_eq!(resp.lease_id.as_deref(), Some("ls-lease-test-123"));
        assert_eq!(resp.ttl_seconds, Some(300));
    }

    #[test]
    fn test_revoke_request_serialization() {
        let req = RevokeRequest {
            version: PROTOCOL_VERSION.to_string(),
            action: "revoke_lease".to_string(),
            lease_id: "ls-lease-xyz".to_string(),
            client_pid: 5678,
        };

        let json_str = serde_json::to_string(&req).expect("Failed to serialize");
        assert!(json_str.contains("\"action\":\"revoke_lease\""));
        assert!(json_str.contains("\"lease_id\":\"ls-lease-xyz\""));
        assert!(json_str.contains("\"client_pid\":5678"));
    }

    #[tokio::test]
    async fn test_live_daemon_ping() {
        let client = LocksmithClient::new();
        if client.is_alive() {
            let res = client.ping().await;
            println!("Daemon ping result: {:?}", res);
            assert!(res.is_ok(), "Expected live ping to succeed");
            assert_eq!(res.unwrap(), "PONG");
        }
    }
}
