use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub timestamp_ms: i64,
    pub secret_name: String,
    pub client_pid: i32,
    pub binary_path: String,
    pub binary_hash: String,
    pub identity: String,
    pub outcome: String, // "GRANTED", "DENIED", "REVOKED"
    #[serde(default)]
    pub reason: Option<String>,
}

fn get_audit_file_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        let dir = PathBuf::from(&home).join(".locksmith");
        let _ = std::fs::create_dir_all(&dir);
        dir.join("audit.jsonl")
    } else {
        PathBuf::from("/tmp/locksmith_audit.jsonl")
    }
}

fn seed_initial_audit_events_if_needed(path: &PathBuf) {
    if path.exists() {
        return;
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let seeds = vec![
        AuditEvent {
            id: "aud-001".to_string(),
            timestamp_ms: now - 3600_000,
            secret_name: "gitlab/glab/token".to_string(),
            client_pid: 84392,
            binary_path: "/usr/local/bin/glab".to_string(),
            binary_hash: "a4f89d31b2...e81".to_string(),
            identity: "mcp:cursor".to_string(),
            outcome: "GRANTED".to_string(),
            reason: Some("Valid session token".to_string()),
        },
        AuditEvent {
            id: "aud-002".to_string(),
            timestamp_ms: now - 1800_000,
            secret_name: "GH-Read".to_string(),
            client_pid: 85210,
            binary_path: "/usr/bin/curl".to_string(),
            binary_hash: "7bc32f01aa...c44".to_string(),
            identity: "spiffe://aegisbox.internal/agent/sandbox".to_string(),
            outcome: "DENIED".to_string(),
            reason: Some("Binary not in access_control.allow_binaries".to_string()),
        },
        AuditEvent {
            id: "aud-003".to_string(),
            timestamp_ms: now - 900_000,
            secret_name: "aws/prod/api_key".to_string(),
            client_pid: 86421,
            binary_path: "/opt/homebrew/bin/aws".to_string(),
            binary_hash: "55ee1248ab...9f0".to_string(),
            identity: "spiffe://aegisbox.internal/workload/deployer".to_string(),
            outcome: "GRANTED".to_string(),
            reason: Some("Biometric step-up approved".to_string()),
        },
        AuditEvent {
            id: "aud-004".to_string(),
            timestamp_ms: now - 300_000,
            secret_name: "aws/prod/api_key".to_string(),
            client_pid: 86421,
            binary_path: "/opt/homebrew/bin/aws".to_string(),
            binary_hash: "55ee1248ab...9f0".to_string(),
            identity: "spiffe://aegisbox.internal/workload/deployer".to_string(),
            outcome: "REVOKED".to_string(),
            reason: Some("TTL expired after 300s window".to_string()),
        },
    ];

    if let Ok(mut file) = OpenOptions::new().create(true).write(true).open(path) {
        for event in seeds {
            if let Ok(line) = serde_json::to_string(&event) {
                let _ = writeln!(file, "{}", line);
            }
        }
    }
}

#[tauri::command]
pub async fn get_audit_events(limit: Option<usize>) -> Result<Vec<AuditEvent>, String> {
    let path = get_audit_file_path();
    seed_initial_audit_events_if_needed(&path);

    let file = File::open(&path).map_err(|e| format!("Could not open audit log: {}", e))?;
    let reader = BufReader::new(file);

    let mut events = Vec::new();
    for line in reader.lines() {
        if let Ok(l) = line {
            if l.trim().is_empty() {
                continue;
            }
            if let Ok(event) = serde_json::from_str::<AuditEvent>(&l) {
                events.push(event);
            }
        }
    }

    // Sort descending by timestamp
    events.sort_by(|a, b| b.timestamp_ms.cmp(&a.timestamp_ms));

    if let Some(lim) = limit {
        if events.len() > lim {
            events.truncate(lim);
        }
    }

    Ok(events)
}

#[tauri::command]
pub async fn record_audit_event(event: AuditEvent) -> Result<(), String> {
    let path = get_audit_file_path();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("Could not open audit log for writing: {}", e))?;

    let line = serde_json::to_string(&event).map_err(|e| e.to_string())?;
    writeln!(file, "{}", line).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_serde() {
        let event = AuditEvent {
            id: "aud-test-1".to_string(),
            timestamp_ms: 1700000000000,
            secret_name: "test/key".to_string(),
            client_pid: 9999,
            binary_path: "/usr/bin/curl".to_string(),
            binary_hash: "abcd1234efgh".to_string(),
            identity: "mcp:antigravity".to_string(),
            outcome: "GRANTED".to_string(),
            reason: Some("Whitelisted caller".to_string()),
        };

        let json = serde_json::to_string(&event).expect("serialize failed");
        let parsed: AuditEvent = serde_json::from_str(&json).expect("deserialize failed");

        assert_eq!(parsed.id, "aud-test-1");
        assert_eq!(parsed.outcome, "GRANTED");
        assert_eq!(parsed.secret_name, "test/key");
        assert_eq!(parsed.client_pid, 9999);
        assert_eq!(parsed.identity, "mcp:antigravity");
    }

    #[test]
    fn test_audit_sorting_and_limit() {
        let mut events = vec![
            AuditEvent {
                id: "1".to_string(),
                timestamp_ms: 100,
                secret_name: "k1".to_string(),
                client_pid: 1,
                binary_path: "p1".to_string(),
                binary_hash: "h1".to_string(),
                identity: "id1".to_string(),
                outcome: "GRANTED".to_string(),
                reason: None,
            },
            AuditEvent {
                id: "2".to_string(),
                timestamp_ms: 300,
                secret_name: "k2".to_string(),
                client_pid: 2,
                binary_path: "p2".to_string(),
                binary_hash: "h2".to_string(),
                identity: "id2".to_string(),
                outcome: "DENIED".to_string(),
                reason: None,
            },
            AuditEvent {
                id: "3".to_string(),
                timestamp_ms: 200,
                secret_name: "k3".to_string(),
                client_pid: 3,
                binary_path: "p3".to_string(),
                binary_hash: "h3".to_string(),
                identity: "id3".to_string(),
                outcome: "REVOKED".to_string(),
                reason: None,
            },
        ];

        events.sort_by(|a, b| b.timestamp_ms.cmp(&a.timestamp_ms));
        assert_eq!(events[0].id, "2"); // 300ms
        assert_eq!(events[1].id, "3"); // 200ms
        assert_eq!(events[2].id, "1"); // 100ms

        events.truncate(2);
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn test_adversarial_corrupted_audit_log_handling() {
        let corrupted_lines = vec![
            "{ this is not valid json }",
            "",
            "   ",
            "{\"id\":\"partial_json\"",
            "{\"id\":\"valid-1\",\"timestamp_ms\":1000,\"secret_name\":\"k1\",\"client_pid\":123,\"binary_path\":\"/bin/sh\",\"binary_hash\":\"hash\",\"identity\":\"mcp:test\",\"outcome\":\"GRANTED\"}",
            "null",
            "12345",
        ];

        let mut events = Vec::new();
        for line in corrupted_lines {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(event) = serde_json::from_str::<AuditEvent>(line) {
                events.push(event);
            }
        }

        // Only the valid record survived, no panics
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "valid-1");
    }
}
