<script lang="ts">
  import { auditStore } from "../stores/auditStore.svelte";
  import StatusBadge from "./StatusBadge.svelte";

  function formatTime(timestampMs: number): string {
    const d = new Date(timestampMs);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  function formatDate(timestampMs: number): string {
    const d = new Date(timestampMs);
    return d.toLocaleDateString([], { month: "short", day: "numeric" });
  }
</script>

<div class="space-y-4">
  <!-- Controls & Filters Bar -->
  <div class="flex items-center justify-between flex-wrap gap-2">
    <div>
      <h2 class="text-base font-semibold tracking-tight text-zinc-100 flex items-center space-x-2">
        <span>Access Audit Trail</span>
        <span class="text-xs font-mono font-normal bg-zinc-800 text-zinc-400 px-2 py-0.5 rounded-full border border-zinc-700/60">
          {auditStore.filteredEvents.length} Events
        </span>
      </h2>
      <p class="text-xs text-zinc-400 mt-0.5">
        Zero-trust verification history detailing caller PID, binary SHA-256, and identity assertions.
      </p>
    </div>

    <div class="flex items-center space-x-2">
      <!-- Search Filter -->
      <div class="relative">
        <input
          type="text"
          placeholder="Filter secrets, binaries, PIDs..."
          bind:value={auditStore.searchQuery}
          class="bg-zinc-900 border border-zinc-700/80 rounded-md px-2.5 py-1 text-xs text-zinc-200 placeholder-zinc-500 font-sans focus:outline-none focus:border-cyan-500 w-48"
        />
        {#if auditStore.searchQuery}
          <button
            onclick={() => (auditStore.searchQuery = "")}
            class="absolute right-2 top-1.5 text-zinc-500 hover:text-zinc-300 text-xs"
          >
            ✕
          </button>
        {/if}
      </div>

      <!-- Outcome Selector -->
      <select
        bind:value={auditStore.outcomeFilter}
        class="bg-zinc-900 border border-zinc-700/80 rounded-md px-2 py-1 text-xs text-zinc-200 font-sans focus:outline-none focus:border-cyan-500"
      >
        <option value="ALL">All Outcomes</option>
        <option value="GRANTED">GRANTED</option>
        <option value="DENIED">DENIED</option>
        <option value="REVOKED">REVOKED</option>
      </select>

      <!-- Refresh -->
      <button
        onclick={() => auditStore.refresh()}
        class="text-xs font-medium bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 px-2.5 py-1.5 rounded-md transition-colors"
        title="Refresh Audit Logs"
      >
        <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
        </svg>
      </button>
    </div>
  </div>

  <!-- Audit Table -->
  <div class="border border-zinc-800 rounded-lg overflow-hidden bg-zinc-900/30 backdrop-blur-sm">
    <div class="overflow-x-auto">
      <table class="w-full text-left text-xs">
        <thead class="bg-zinc-900/70 border-b border-zinc-800 text-zinc-400 font-mono">
          <tr>
            <th class="py-2.5 px-3 font-medium w-28">Timestamp</th>
            <th class="py-2.5 px-3 font-medium w-24">Outcome</th>
            <th class="py-2.5 px-3 font-medium">Secret Key</th>
            <th class="py-2.5 px-3 font-medium">Caller & Executable</th>
            <th class="py-2.5 px-3 font-medium">Binary SHA-256</th>
            <th class="py-2.5 px-3 font-medium">Workload Identity</th>
            <th class="py-2.5 px-3 font-medium">Verification Note</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-zinc-800/60 font-sans">
          {#if auditStore.filteredEvents.length === 0}
            <tr>
              <td colspan="7" class="py-8 text-center text-zinc-500 font-mono">
                No matching access audit records found.
              </td>
            </tr>
          {:else}
            {#each auditStore.filteredEvents as ev (ev.id)}
              <tr class="hover:bg-zinc-800/30 transition-colors">
                <!-- Timestamp -->
                <td class="py-2.5 px-3 font-mono text-zinc-400">
                  <div class="flex flex-col">
                    <span class="text-zinc-200">{formatTime(ev.timestamp_ms)}</span>
                    <span class="text-[10px] text-zinc-500">{formatDate(ev.timestamp_ms)}</span>
                  </div>
                </td>

                <!-- Outcome -->
                <td class="py-2.5 px-3">
                  <StatusBadge status={ev.outcome} />
                </td>

                <!-- Secret Key -->
                <td class="py-2.5 px-3 font-mono font-medium text-zinc-100">
                  {ev.secret_name}
                </td>

                <!-- Caller Executable & PID -->
                <td class="py-2.5 px-3">
                  <div class="flex flex-col">
                    <span class="text-zinc-200 font-mono text-[11px] truncate max-w-[160px]" title={ev.binary_path}>
                      {ev.binary_path.split('/').pop()}
                    </span>
                    <span class="text-[10px] text-zinc-500 font-mono">PID {ev.client_pid}</span>
                  </div>
                </td>

                <!-- Binary Hash -->
                <td class="py-2.5 px-3 font-mono text-zinc-400 text-[11px]">
                  <span class="bg-zinc-800/60 px-1 py-0.5 rounded border border-zinc-700/50" title={ev.binary_hash}>
                    {ev.binary_hash.substring(0, 12)}...
                  </span>
                </td>

                <!-- Workload Identity -->
                <td class="py-2.5 px-3">
                  {#if ev.identity.startsWith("spiffe://")}
                    <span class="font-mono text-cyan-400 text-[11px] bg-cyan-950/40 border border-cyan-800/40 px-1.5 py-0.5 rounded" title={ev.identity}>
                      {ev.identity.replace("spiffe://aegisbox.internal/", "spiffe://")}
                    </span>
                  {:else if ev.identity.startsWith("mcp:")}
                    <span class="font-mono text-purple-400 text-[11px] bg-purple-950/40 border border-purple-800/40 px-1.5 py-0.5 rounded">
                      {ev.identity}
                    </span>
                  {:else}
                    <span class="font-mono text-zinc-400 text-[11px]">{ev.identity}</span>
                  {/if}
                </td>

                <!-- Note / Reason -->
                <td class="py-2.5 px-3 text-zinc-400 text-xs truncate max-w-[180px]" title={ev.reason ?? ""}>
                  {ev.reason ?? "—"}
                </td>
              </tr>
            {/each}
          {/if}
        </tbody>
      </table>
    </div>
  </div>
</div>
