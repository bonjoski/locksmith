# 🔐 Locksmith: Technical Specification Documentation (v2)

**Overview:** Locksmith is a secure, cross-platform, biometric-protected keychain vault designed to manage sensitive credentials (keys, tokens, passwords). It ensures that secrets are never exposed in plaintext and access requires hardware-backed authentication, making it suitable for modern DevOps and AI-assisted workflows.

---

## 1. Overall Architecture and Module Relationships

The architecture follows a layered approach, separating the user interface (CLI), the core business logic, and the platform-specific secure storage mechanisms.

### ⚡️ Architectural Diagram (Component Interaction)

```mermaid
graph TD
    subgraph "Interface Layer (cmd/)"
        CLI["locksmith cmd"]
        Summon["summon-locksmith"]
    end
    
    subgraph "Core Logic (pkg/locksmith)"
        LS["Locksmith Controller"]
        Cache["Disk Cache (AES-GCM)"]
        Model["Secret/Metadata Models"]
    end
    
    subgraph "Native Bridge (pkg/native)"
        Bridge["Platform Bridge Interface"]
        Darwin["macOS Keychain + LocalAuth"]
        Windows["Windows Credential Manager + Hello"]
        Linux["Linux Secret Service + Polkit"]
    end
    
    CLI --> LS
    Summon --> LS
    LS --> Cache
    LS --> Model
    LS --> Bridge
    Bridge --> Darwin
    Bridge --> Windows
    Bridge --> Linux
    Cache -.->|Encrypted files| Disk["~/.locksmith/cache/"]
```

### 🌐 Module Relationships

*   **`cmd/` (Interface Layer):** Contains the CLI entry points (`root.go`) for direct user interaction (`locksmith`, `summon-locksmith`).
*   **`pkg/locksmith` (Core Logic):** This is the main public API and controller. It orchestrates the flow by interacting with the `Cache` and abstracting the backend calls through the `Backend` interface.
    *   **`Cache`**: Manages fast, temporary access to keys using encrypted disk storage (AES-256-GCM).
    *   **`Backend`**: Defines the methods (`Set`, `Get`, `Delete`, `List`) required for secure, platform-native storage. This abstraction allows the core logic to be platform-agnostic.
    *   **`Models`**: Contains all data structures, including `Secret`, `SecretMetadata`, and logic for determining expiration status.
*   **`pkg/native` (Platform Bridge):** Implementations for `Backend` that interface directly with OS services:
    *   `masterkey_darwin.go`: macOS Keychain integration.
    *   `masterkey_windows.go`: Windows Credential Manager integration.
    *   `masterkey_linux.go`: Linux Secret Service (DBus/Polkit) integration.

### 🛡️ Security Boundaries and Data Flow

**Data Flow: Retrieving a Secret (`l.getSecret(key)`):**

1.  **Check Cache (Fast Path):** `Locksmith` first checks the in-memory-mapped cache. If the secret is found and not expired, it's returned immediately (high performance).
2.  **Keychain Fallback (Secure Path):** If cache misses or is expired, `Locksmith` calls the `Backend.Get()`.
    *   The `Options` dictates whether biometric authentication is mandatory (`RequireBiometrics`).
    *   The `DefaultBackend` translates this request to the platform-specific bridge (`pkg/native`).
    *   The native bridge triggers the OS-level biometric prompt (Touch ID, Windows Hello, etc.).
3.  **Persistence & Zeroing:** Upon successful retrieval, the secret is loaded into the `Secret` struct, and a copy is returned. The `Secret.Zero()` function ensures the sensitive data buffer is zeroed out of memory immediately after the operation to prevent memory scraping. The data is then re-cached.

---

## 2. APIs and Endpoints

### A. CLI Endpoints (Internal API Gateway)

| Endpoint | Method | Description | Inputs | Outputs | Security |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `locksmith add <key>` | `POST` | Stores a new secret key/token. | `<key>` (Secret Identifier), `--expires <duration>` (Optional). | Success status. | Requires Biometrics (configurable). |
| `locksmith get <key>` | `GET` | Retrieves a secret value. | `<key>`. | Raw secret value (bytes). Prints expiration warnings to `stderr`. | Requires Biometrics. |
| `locksmith list` | `GET` | Lists all stored secret keys and their metadata. | None. | Table format listing key, creation date, expiration date, and status (Valid/Expiring/Expired). | May require Biometrics (for enumeration). |
| `locksmith delete <key>` | `DELETE` | Deletes a secret key entirely. | `<key>`. | Success status. | Requires Biometrics. |
| `locksmith mcp` | `CLI/Tool` | Starts the Model Context Protocol server endpoint (used by AI agents). | None. | Listens on a local port, exposing specific secured tool endpoints. | Biometrics enforce access. |

### B. Go Library API (`*Locksmith`)

The core logic is exposed via the `Locksmith` struct methods.

| Method | Input Parameters | Output/Return Values | Description |
| :--- | :--- | :--- | :--- |
| `NewWithOptions(opts Options)` | `Options` struct (e.g., `RequireBiometrics`). | `(*Locksmith, error)` | Initializes the controller, derives the master key, and sets up the cache. |
| `Get(key string)` | `key` (string) - The secret identifier. | `([]byte, error)` | Retrieves the secret value after checking cache and performing secure fallback. |
| `ListWithMetadata()` | None. | `(map[string]*SecretMetadata, error)` | Retrieves metadata (creation/expiry dates) for all managed keys. |
| `Set(key, secret, ttl)` | `key`, `Secret` struct, `time.Duration`. | `error` | Writes a new secret, updating both the cache and the native keychain. |

### C. Input/Output Specifications

| Field | Type | Description | Example |
| :--- | :--- | :--- | :--- |
| **Key** | `string` | The unique, user-defined identifier for the secret. | `aws/access-key` |
| **Secret Value** | `[]byte` | The raw encrypted data/key. | `AKIAIOSFODNN7EXAMPLE` |
| **TTL/Expiry** | `time.Duration` | How long the secret should be retained. | `72h`, `30d` (30 days). |
| **Output (JSON)** | JSON Object | Standardized response for programmatic access. | `{"key": "...", "value": "...", "expires_in": "48h0m0s", ...}` |

---

## 3. Core Data Structures and Business Logic Flows

### 🧬 Core Data Structures

1.  **`Secret`** (`pkg/locksmith/models.go`):
    *   `Value`: `[]byte` (The actual credential data).
    *   `CreatedAt`: `time.Time` (Timestamp of creation).
    *   `ExpiresAt`: `time.Time` (Timestamp when the secret becomes invalid).
    *   **Critical Method**: `Zero()`: Explicitly overwrites the `Value` byte array to prevent memory exposure.
2.  **`SecretMetadata`** (`pkg/locksmith/models.go`):
    *   `CreatedAt`: `time.Time`
    *   `ExpiresAt`: `time.Time`
    *   Used for listing keys without retrieving the secret value.
3.  **`Options`** (`pkg/locksmith/locksmith.go`):
    *   `RequireBiometrics`: A boolean flag that dictates if the secure backend call must prompt the operating system for biometrics.
    *   `PromptMessage`: Allows customization of the security prompt shown to the user.

### ⚙️ Key Business Logic Flows

1.  **Expiration/Status Management**:
    *   `Secret.GetExpirationStatus()`: Calculates the status (`Valid`, `Expiring`, `Expired`) by comparing the current time against the `ExpiresAt` timestamp and an optional configurable `threshold` (e.g., `7d`).
    *   The CLI prominently displays these statuses in the list view, providing proactive warning for secrets approaching expiration.
2.  **Configuration Handling (`cmd/locksmith/cmd/root.go`):**
    *   The `PersistentPreRunE` function ensures that system configuration (`Config`) is loaded, and crucially, it initializes the `Locksmith` controller using the proper `Options`, making the system ready for execution before any command runs.
3.  **Authorization Gate (Biometrics)**:
    *   Implementation is delegated to the `Backend` interface. If `Options.RequireBiometrics` is `true`, the `Backend.Get()` call **will fail** without a successful OS-level biometric challenge handled by the native bridge.

---

## 4. Setup and Usage Guidelines

### 🛠️ Setup Guide

#### Prerequisite Tools
* **Go:** Version 1.25.4 (Recommended).
* **Platform:** macOS, Windows, or Linux.
* **macOS:** Xcode Command Line Tools (`xcode-select --install`) and an Apple Developer ID (Recommended).

#### Installation Methods (Recommended)

1.  **Homebrew (macOS - Preferred):**
    ```bash
    brew tap bonjoski/locksmith
    brew install locksmith
    ```
2.  **Building from Source:**
    ```bash
    git clone https://github.com/bonjoski/locksmith.git
    cd locksmith
    make build  # Compiles all necessary platform binaries
    make sign   # Signs the binary for secure distribution
    ```

#### Configuration (`~/.locksmith/config.yml`)
Saves configuration details, primarily for fine-tuning security behavior:

```yaml
auth:
  require_biometrics: true  # Forces biometrics on all operations
  prompt_message: "Authenticate to access Locksmith secret '%s'" # Custom prompt
notifications:
  expiring_threshold: 7d    # Warning given 7 days before expiration
  method: macos              # Display using OS native notification
  show_on_get: true
```

### 🚀 Usage Guidelines

#### Basic CLI Usage
| Action | Command | Notes |
| :--- | :--- | :--- |
| **Store Secret** | `locksmith add my-service my-password --expires 30d` | Sets the name, value, and 30-day expiry. |
| **Retrieve Secret** | `locksmith get my-service` | Prompts for biometrics. Prints value and warnings to stdout/stderr. |
| **List Keys** | `locksmith list` | Shows all keys and their current status (Valid, Expiring, Expired). |
| **Remove Secret** | `locksmith delete my-service` | Permanently removes the key from all storage layers. |

#### Advanced Usage: DevOps Integration (Summon)
Locksmith supports the **Summon** tool, allowing secrets to be injected securely into environment variables for deployment scripts.
1.  Place secrets in a `secrets.yml` file, referencing the Locksmith key:
    ```yaml
    AWS_ACCESS_KEY_ID: !var aws/access-key
    ```
2.  Run the target command using Summon and the Locksmith provider:
    ```bash
    summon --provider locksmith -f secrets.yml docker run myapp
    ```

#### AI & Model Context Protocol (MCP)
Locksmith includes a dedicated MCP server (`locksmith mcp`). Developers can integrate this into AI tools (e.g., Cursor).
*   **Purpose:** Allows AI agents to treat the vault as a secure, read-only function call.
*   **Procedure:** Configure the AI tool to point to the `locksmith` command binary. The AI's request for a secret will trigger the mandatory biometric gate on the user's machine, ensuring the AI never bypasses hardware security. The MCP server explicitly bypasses any disk caches and does not expose `set` or `delete` tools, ensuring AI agents cannot silently modify or destroy credentials.