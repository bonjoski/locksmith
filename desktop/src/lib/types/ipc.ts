export interface ActiveLeaseItem {
  lease_id: string;
  secret_name: string;
  client_pid: number;
  process_start_time: number;
  client_binary_hash: string;
  spiffe_id?: string;
  created_at: string;
  expires_at: string;
  max_uses: number;
  uses_count: number;
  session_ticket_id?: string;
  revoked: boolean;
}

export interface DaemonStatus {
  online: boolean;
  socket_path: string;
  version: string;
  active_leases_count: number;
}

export interface AuditEvent {
  id: string;
  timestamp_ms: number;
  secret_name: string;
  client_pid: number;
  binary_path: string;
  binary_hash: string;
  identity: string;
  outcome: "GRANTED" | "DENIED" | "REVOKED";
  reason?: string;
}

export interface SecretItem {
  key: string;
  secret_type: string;
  owner_application: string;
  source_url: string;
  created_at: string;
  expires_at: string;
  status: "StatusValid" | "StatusExpiring" | "StatusExpired";
  metadata: Record<string, string>;
}

export interface RotationRuleItem {
  secret: string;
  rotator: string;
  secret_type: string;
  owner_application: string;
  source_url?: string;
  ttl: string;
  metadata: Record<string, string>;
}

export interface AccessControlItem {
  allow_binaries: string[];
  deny_binaries: string[];
}
