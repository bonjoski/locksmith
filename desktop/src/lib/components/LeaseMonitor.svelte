<script lang="ts">
  import { onMount } from "svelte";
  import { leaseStore } from "../stores/leaseStore.svelte";
  import StatusBadge from "./StatusBadge.svelte";
  import type { ActiveLeaseItem } from "../types/ipc";

  let nowMs = $state(Date.now());
  let showRequestModal = $state(false);
  let testSecretName = $state("gitlab/glab/token");
  let testTTL = $state(300);
  let testMaxUses = $state(5);

  onMount(() => {
    const timer = setInterval(() => {
      nowMs = Date.now();
    }, 1000);
    return () => clearInterval(timer);
  });

  function getTTLStats(lease: ActiveLeaseItem) {
    const created = new Date(lease.created_at).getTime();
    const expires = new Date(lease.expires_at).getTime();
    const total = Math.max(1, expires - created);
    const remaining = Math.max(0, expires - nowMs);
    const progress = Math.min(100, Math.max(0, (remaining / total) * 100));
    const secondsLeft = Math.ceil(remaining / 1000);

    return {
      progress,
      secondsLeft,
      isExpired: remaining <= 0,
    };
  }

  function formatTimeLeft(seconds: number): string {
    if (seconds <= 0) return "Expired";
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    if (mins > 0) {
      return `${mins}m ${secs}s`;
    }
    return `${secs}s`;
  }

  async function handleRevoke(leaseId: string) {
    await leaseStore.revoke(leaseId);
  }

  async function handleCreateTestLease() {
    await leaseStore.requestTestLease(testSecretName, testTTL, testMaxUses);
    showRequestModal = false;
  }
</script>

<div class="space-y-4">
  <!-- Header / Controls Bar -->
  <div class="flex items-center justify-between">
    <div>
      <h2 class="text-base font-semibold tracking-tight text-zinc-100 flex items-center space-x-2">
        <span>Active Ephemeral Leases</span>
        <span class="text-xs font-mono font-normal bg-zinc-800 text-zinc-400 px-2 py-0.5 rounded-full border border-zinc-700/60">
          {leaseStore.leases.filter((l) => !l.revoked).length} Active
        </span>
      </h2>
      <p class="text-xs text-zinc-400 mt-0.5">
        Live ETX monitor observing process bindings with PID-recycling validation.
      </p>
    </div>

    <div class="flex items-center space-x-2">
      <button
        onclick={() => (showRequestModal = true)}
        class="text-xs font-medium bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-400 border border-cyan-500/30 px-3 py-1.5 rounded-md transition-colors flex items-center space-x-1.5"
      >
        <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
        </svg>
        <span>Request Ephemeral Lease</span>
      </button>

      <button
        onclick={() => leaseStore.refresh()}
        class="text-xs font-medium bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 px-2.5 py-1.5 rounded-md transition-colors"
        title="Refresh Leases"
      >
        <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
        </svg>
      </button>
    </div>
  </div>

  <!-- Leases Table -->
  <div class="border border-zinc-800 rounded-lg overflow-hidden bg-zinc-900/30 backdrop-blur-sm">
    <div class="overflow-x-auto">
      <table class="w-full text-left text-xs">
        <thead class="bg-zinc-900/70 border-b border-zinc-800 text-zinc-400 font-mono">
          <tr>
            <th class="py-2.5 px-3 font-medium">Lease ID</th>
            <th class="py-2.5 px-3 font-medium">Secret</th>
            <th class="py-2.5 px-3 font-medium">Target / Workload</th>
            <th class="py-2.5 px-3 font-medium">PID & Liveness</th>
            <th class="py-2.5 px-3 font-medium w-48">TTL Remaining</th>
            <th class="py-2.5 px-3 font-medium">Usage</th>
            <th class="py-2.5 px-3 font-medium text-right">Kill Switch</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-zinc-800/60 font-sans">
          {#if leaseStore.leases.length === 0}
            <tr>
              <td colspan="7" class="py-8 text-center text-zinc-500 font-mono">
                No active ephemeral credential leases in flight.
              </td>
            </tr>
          {:else}
            {#each leaseStore.leases as lease (lease.lease_id)}
              {@const ttl = getTTLStats(lease)}
              <tr class="hover:bg-zinc-800/30 transition-colors {lease.revoked ? 'opacity-40' : ''}">
                <!-- Lease ID -->
                <td class="py-2.5 px-3 font-mono text-zinc-300">
                  <div class="flex items-center space-x-1.5">
                    <span class="truncate max-w-[120px]" title={lease.lease_id}>
                      {lease.lease_id}
                    </span>
                  </div>
                </td>

                <!-- Secret -->
                <td class="py-2.5 px-3 font-semibold text-zinc-100">
                  <div class="flex items-center space-x-1.5">
                    <span class="w-2 h-2 rounded-full {lease.revoked ? 'bg-zinc-600' : ttl.isExpired ? 'bg-rose-500' : 'bg-emerald-500'}"></span>
                    <span>{lease.secret_name}</span>
                  </div>
                </td>

                <!-- Target / Workload -->
                <td class="py-2.5 px-3 text-zinc-400">
                  {#if lease.spiffe_id}
                    <span class="font-mono text-cyan-400 text-[11px] bg-cyan-950/40 border border-cyan-800/40 px-1.5 py-0.5 rounded" title={lease.spiffe_id}>
                      {lease.spiffe_id.replace("spiffe://aegisbox.internal/", "spiffe://")}
                    </span>
                  {:else}
                    <span class="text-zinc-500 font-mono text-[11px]">POSIX Process</span>
                  {/if}
                </td>

                <!-- PID & Liveness -->
                <td class="py-2.5 px-3 font-mono">
                  <div class="flex items-center space-x-1.5">
                    <span class="text-zinc-300">PID: {lease.client_pid}</span>
                    <span
                      class="px-1.5 py-0.2 rounded text-[10px] border {lease.revoked ? 'bg-zinc-800 text-zinc-500 border-zinc-700' : 'bg-emerald-950/50 text-emerald-400 border-emerald-800/40'}"
                      title="PID recycle protection verified (start_time: {lease.process_start_time})"
                    >
                      ✓ Bound
                    </span>
                  </div>
                </td>

                <!-- TTL Progress -->
                <td class="py-2.5 px-3">
                  <div class="space-y-1">
                    <div class="flex items-center justify-between text-[11px] font-mono">
                      <span class="{ttl.isExpired ? 'text-rose-400 font-bold' : 'text-zinc-300'}">
                        {formatTimeLeft(ttl.secondsLeft)}
                      </span>
                      <span class="text-zinc-500 text-[10px]">
                        {Math.round(ttl.progress)}%
                      </span>
                    </div>
                    <progress
                      max="100"
                      value={ttl.progress}
                      class="w-full h-1.5 block rounded-full"
                    ></progress>
                  </div>
                </td>

                <!-- Usage -->
                <td class="py-2.5 px-3 font-mono text-zinc-300">
                  <span class="font-semibold text-zinc-100">{lease.uses_count}</span>
                  <span class="text-zinc-500">/</span>
                  <span class="text-zinc-400">{lease.max_uses > 0 ? lease.max_uses : '∞'}</span>
                </td>

                <!-- Kill Switch Button -->
                <td class="py-2.5 px-3 text-right">
                  {#if lease.revoked}
                    <span class="text-zinc-600 font-mono text-xs">Revoked</span>
                  {:else}
                    <button
                      onclick={() => handleRevoke(lease.lease_id)}
                      class="text-xs bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 px-2.5 py-1 rounded transition-colors font-medium shadow-sm active:scale-95"
                    >
                      Revoke Lease
                    </button>
                  {/if}
                </td>
              </tr>
            {/each}
          {/if}
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- Quick Request Modal -->
{#if showRequestModal}
  <div class="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
    <div class="bg-zinc-900 border border-zinc-800 rounded-xl max-w-md w-full p-5 space-y-4 shadow-2xl">
      <div class="flex items-center justify-between border-b border-zinc-800 pb-3">
        <h3 class="text-sm font-semibold text-zinc-100">Request Ephemeral Lease</h3>
        <button
          onclick={() => (showRequestModal = false)}
          class="text-zinc-400 hover:text-zinc-200"
        >
          ✕
        </button>
      </div>

      <div class="space-y-3 text-xs">
        <div>
          <label for="secret-select" class="block text-zinc-400 mb-1">Secret Key</label>
          <select
            id="secret-select"
            bind:value={testSecretName}
            class="w-full bg-zinc-800 border border-zinc-700 rounded px-2.5 py-1.5 text-zinc-100 font-mono text-xs focus:outline-none focus:border-cyan-500"
          >
            <option value="gitlab/glab/token">gitlab/glab/token (OAuth Token)</option>
            <option value="GH-Read">GH-Read (App Installation Token)</option>
            <option value="aws/prod/api_key">aws/prod/api_key (API Key)</option>
          </select>
        </div>

        <div>
          <label for="ttl-input" class="block text-zinc-400 mb-1">TTL (Seconds)</label>
          <input
            id="ttl-input"
            type="number"
            bind:value={testTTL}
            min="10"
            max="3600"
            class="w-full bg-zinc-800 border border-zinc-700 rounded px-2.5 py-1.5 text-zinc-100 font-mono text-xs focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div>
          <label for="max-uses-input" class="block text-zinc-400 mb-1">Max Uses (0 = unlimited)</label>
          <input
            id="max-uses-input"
            type="number"
            bind:value={testMaxUses}
            min="1"
            max="100"
            class="w-full bg-zinc-800 border border-zinc-700 rounded px-2.5 py-1.5 text-zinc-100 font-mono text-xs focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      <div class="flex items-center justify-end space-x-2 pt-2 border-t border-zinc-800">
        <button
          onclick={() => (showRequestModal = false)}
          class="px-3 py-1.5 text-xs text-zinc-400 hover:text-zinc-200 border border-zinc-700 rounded-md"
        >
          Cancel
        </button>
        <button
          onclick={handleCreateTestLease}
          class="px-3 py-1.5 text-xs font-medium bg-cyan-600 hover:bg-cyan-500 text-white rounded-md transition-colors"
        >
          Issue Lease
        </button>
      </div>
    </div>
  </div>
{/if}
