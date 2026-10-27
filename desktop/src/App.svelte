<script lang="ts">
  import { onMount } from "svelte";
  import LeaseMonitor from "./lib/components/LeaseMonitor.svelte";
  import AuditLog from "./lib/components/AuditLog.svelte";
  import VaultDashboard from "./lib/components/VaultDashboard.svelte";
  import RotationPolicy from "./lib/components/RotationPolicy.svelte";
  import StatusBadge from "./lib/components/StatusBadge.svelte";
  import { leaseStore } from "./lib/stores/leaseStore.svelte";
  import { auditStore } from "./lib/stores/auditStore.svelte";
  import { vaultStore } from "./lib/stores/vaultStore.svelte";
  import { rotationStore } from "./lib/stores/rotationStore.svelte";

  type ActiveTab = "leases" | "audit" | "vault" | "rotation";
  let activeTab = $state<ActiveTab>("leases");

  let activeLeaseCount = $derived(
    leaseStore.leases.filter((l) => !l.revoked).length
  );

  onMount(() => {
    // Initial fetch
    leaseStore.refresh();
    auditStore.refresh();
    vaultStore.refresh();
    rotationStore.refresh();

    // Background polling loop
    const pollInterval = setInterval(() => {
      leaseStore.refresh();
    }, 2000);

    return () => clearInterval(pollInterval);
  });
</script>

<main class="h-screen w-screen flex flex-col bg-zinc-950 text-zinc-100 select-none overflow-hidden font-sans">
  <!-- Titlebar / Header -->
  <header class="h-13 border-b border-zinc-800/80 px-4 flex items-center justify-between bg-zinc-900/40 select-none">
    <div class="flex items-center space-x-4">
      <div class="flex items-center space-x-2.5">
        <img src="/icon.png" alt="Locksmith" class="h-6 w-6 rounded-md shadow-sm object-contain" />
        <h1 class="text-sm font-semibold tracking-wide text-zinc-100">
          Locksmith <span class="text-xs text-zinc-500 font-mono">Cockpit</span>
        </h1>
      </div>

      <span class="text-zinc-700">|</span>

      <!-- Daemon Status Pill -->
      <div class="flex items-center space-x-2">
        <StatusBadge
          status={leaseStore.daemonStatus.online ? "ONLINE" : "OFFLINE"}
          label={leaseStore.daemonStatus.online ? "ETX Daemon Connected" : "Daemon Standalone / Mock"}
        />
        {#if leaseStore.daemonStatus.socket_path}
          <span class="text-[11px] font-mono text-zinc-500 truncate max-w-[200px]" title={leaseStore.daemonStatus.socket_path}>
            {leaseStore.daemonStatus.socket_path.split('/').pop()}
          </span>
        {/if}
      </div>
    </div>

    <!-- Right Controls -->
    <div class="flex items-center space-x-3 text-xs">
      <div class="flex items-center space-x-1.5 font-mono text-zinc-400 bg-zinc-900 px-2 py-1 rounded border border-zinc-800">
        <span class="w-2 h-2 rounded-full {activeLeaseCount > 0 ? 'bg-emerald-400' : 'bg-zinc-600'}"></span>
        <span>{activeLeaseCount} Active {activeLeaseCount === 1 ? 'Lease' : 'Leases'}</span>
      </div>

      <button
        onclick={() => {
          leaseStore.refresh();
          auditStore.refresh();
          vaultStore.refresh();
          rotationStore.refresh();
        }}
        class="text-xs font-medium bg-zinc-800 hover:bg-zinc-700 text-zinc-300 border border-zinc-700 px-2.5 py-1 rounded transition-colors"
      >
        Sync All
      </button>
    </div>
  </header>

  <!-- Navigation Tabs -->
  <nav class="h-10 border-b border-zinc-800/80 px-4 flex items-center space-x-1 bg-zinc-900/20 text-xs font-medium">
    <button
      onclick={() => (activeTab = "leases")}
      class="px-3 py-1.5 rounded-md transition-colors flex items-center space-x-1.5 {activeTab === 'leases' ? 'bg-zinc-800 text-cyan-400 font-semibold shadow-sm' : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/40'}"
    >
      <span>⚡</span>
      <span>Ephemeral Lease Monitor</span>
      {#if activeLeaseCount > 0}
        <span class="ml-1 text-[10px] font-mono bg-cyan-950/80 text-cyan-300 border border-cyan-800/60 px-1.5 py-0.2 rounded-full">
          {activeLeaseCount}
        </span>
      {/if}
    </button>

    <button
      onclick={() => (activeTab = "audit")}
      class="px-3 py-1.5 rounded-md transition-colors flex items-center space-x-1.5 {activeTab === 'audit' ? 'bg-zinc-800 text-cyan-400 font-semibold shadow-sm' : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/40'}"
    >
      <span>📜</span>
      <span>Access Audit Trail</span>
    </button>

    <button
      onclick={() => (activeTab = "vault")}
      class="px-3 py-1.5 rounded-md transition-colors flex items-center space-x-1.5 {activeTab === 'vault' ? 'bg-zinc-800 text-cyan-400 font-semibold shadow-sm' : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/40'}"
    >
      <span>🎯</span>
      <span>Expiration Radar</span>
    </button>

    <button
      onclick={() => (activeTab = "rotation")}
      class="px-3 py-1.5 rounded-md transition-colors flex items-center space-x-1.5 {activeTab === 'rotation' ? 'bg-zinc-800 text-cyan-400 font-semibold shadow-sm' : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/40'}"
    >
      <span>🔄</span>
      <span>Auto-Rotation & Policies</span>
    </button>
  </nav>

  <!-- Main View Area -->
  <div class="flex-1 overflow-y-auto p-4 select-text">
    {#if activeTab === "leases"}
      <LeaseMonitor />
    {:else if activeTab === "audit"}
      <AuditLog />
    {:else if activeTab === "vault"}
      <VaultDashboard />
    {:else if activeTab === "rotation"}
      <RotationPolicy />
    {/if}
  </div>

  <!-- Footer / Status Bar -->
  <footer class="h-6 border-t border-zinc-800/80 px-4 flex items-center justify-between bg-zinc-950 text-[10px] text-zinc-500 font-mono select-none">
    <div class="flex items-center space-x-4">
      <span>ETX v1.0 Security Fabric</span>
      <span>•</span>
      <span>PID-Recycling Verification Active</span>
      <span>•</span>
      <span>Biometric Step-Up: Touch ID / Apple Watch</span>
    </div>

    <div class="flex items-center space-x-3">
      <span>Locksmith Cockpit v2.10.0</span>
    </div>
  </footer>
</main>
