<script lang="ts">
  import { rotationStore } from "../stores/rotationStore.svelte";

  let newBinaryPath = $state("");

  async function handleAddBinary() {
    if (!newBinaryPath.trim()) return;
    await rotationStore.addAllowBinary(newBinaryPath.trim());
    newBinaryPath = "";
  }

  async function handleRemoveBinary(path: string) {
    await rotationStore.removeAllowBinary(path);
  }
</script>

<div class="space-y-6">
  <!-- Rotation Rules Matrix -->
  <div class="space-y-3">
    <div class="flex items-center justify-between">
      <div>
        <h3 class="text-sm font-semibold tracking-tight text-zinc-100 flex items-center space-x-2">
          <span>Auto-Rotation Rules Matrix</span>
          <span class="text-xs font-mono font-normal bg-zinc-800 text-zinc-400 px-2 py-0.5 rounded-full border border-zinc-700/60">
            {rotationStore.rules.length} Policies
          </span>
        </h3>
        <p class="text-xs text-zinc-400 mt-0.5">
          Active automated rotator rules configured in <code class="font-mono text-zinc-300">~/.locksmith/config.yml</code>.
        </p>
      </div>

      <button
        onclick={() => rotationStore.refresh()}
        class="text-xs font-medium bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 px-2.5 py-1.5 rounded-md transition-colors"
        title="Reload Configuration"
      >
        <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
        </svg>
      </button>
    </div>

    {#if rotationStore.rotationMessage}
      <div class="p-3 bg-emerald-950/40 border border-emerald-500/30 rounded-lg text-xs text-emerald-300 font-mono">
        ✓ {rotationStore.rotationMessage}
      </div>
    {/if}

    <div class="border border-zinc-800 rounded-lg overflow-hidden bg-zinc-900/30 backdrop-blur-sm">
      <div class="overflow-x-auto">
        <table class="w-full text-left text-xs">
          <thead class="bg-zinc-900/70 border-b border-zinc-800 text-zinc-400 font-mono">
            <tr>
              <th class="py-2.5 px-3 font-medium">Secret Pattern</th>
              <th class="py-2.5 px-3 font-medium">Rotator Handler ID</th>
              <th class="py-2.5 px-3 font-medium">Type</th>
              <th class="py-2.5 px-3 font-medium">Schedule / TTL</th>
              <th class="py-2.5 px-3 font-medium">Metadata Ref</th>
              <th class="py-2.5 px-3 font-medium text-right">Action</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-zinc-800/60 font-sans">
            {#each rotationStore.rules as rule (rule.secret)}
              <tr class="hover:bg-zinc-800/30 transition-colors">
                <!-- Secret Pattern -->
                <td class="py-2.5 px-3 font-mono font-semibold text-zinc-100">
                  {rule.secret}
                </td>

                <!-- Handler -->
                <td class="py-2.5 px-3 font-mono text-cyan-400">
                  <span class="bg-cyan-950/40 border border-cyan-800/40 px-1.5 py-0.5 rounded text-[11px]">
                    {rule.rotator}
                  </span>
                </td>

                <!-- Type -->
                <td class="py-2.5 px-3 font-mono text-zinc-400">
                  {rule.secret_type || 'generic'}
                </td>

                <!-- Schedule / TTL -->
                <td class="py-2.5 px-3 font-mono text-zinc-300">
                  <span class="bg-zinc-800 px-1.5 py-0.5 rounded text-[11px] border border-zinc-700/60 font-semibold">
                    {rule.ttl || 'default'}
                  </span>
                </td>

                <!-- Metadata Ref -->
                <td class="py-2.5 px-3 font-mono text-[11px] text-zinc-400">
                  {#if Object.keys(rule.metadata).length > 0}
                    <div class="truncate max-w-[200px]" title={JSON.stringify(rule.metadata)}>
                      {Object.keys(rule.metadata).length} refs ({Object.keys(rule.metadata).join(', ')})
                    </div>
                  {:else}
                    <span class="text-zinc-600">None</span>
                  {/if}
                </td>

                <!-- Action -->
                <td class="py-2.5 px-3 text-right">
                  <button
                    disabled={rotationStore.rotatingSecret === rule.secret}
                    onclick={() => rotationStore.triggerRotate(rule.secret)}
                    class="text-xs bg-cyan-600/10 hover:bg-cyan-600/20 text-cyan-400 border border-cyan-500/30 px-2.5 py-1 rounded transition-colors font-medium disabled:opacity-50"
                  >
                    {#if rotationStore.rotatingSecret === rule.secret}
                      Rotating...
                    {:else}
                      Rotate Now
                    {/if}
                  </button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Binary Whitelist / Access Control Management -->
  <div class="space-y-3 pt-2">
    <div>
      <h3 class="text-sm font-semibold tracking-tight text-zinc-100 flex items-center space-x-2">
        <span>Application Access Control & Binary Whitelist</span>
      </h3>
      <p class="text-xs text-zinc-400 mt-0.5">
        Restricts secret retrieval and ephemeral lease issuance to verified executables on disk.
      </p>
    </div>

    <!-- Allow Binaries -->
    <div class="bg-zinc-900/40 border border-zinc-800 rounded-lg p-4 space-y-3">
      <div class="flex items-center justify-between">
        <div class="text-xs font-mono font-medium text-emerald-400 flex items-center space-x-1.5">
          <span>✓ Authorized Executables (allow_binaries)</span>
        </div>
      </div>

      <div class="flex items-center space-x-2">
        <input
          type="text"
          placeholder="/path/to/trusted/executable (e.g. /opt/homebrew/bin/glab)"
          bind:value={newBinaryPath}
          class="flex-1 bg-zinc-950 border border-zinc-700/80 rounded px-2.5 py-1.5 text-xs text-zinc-200 placeholder-zinc-500 font-mono focus:outline-none focus:border-cyan-500"
        />
        <button
          onclick={handleAddBinary}
          class="text-xs font-medium bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/40 px-3 py-1.5 rounded transition-colors whitespace-nowrap"
        >
          Add Binary
        </button>
      </div>

      <div class="flex flex-wrap gap-2 pt-1">
        {#each rotationStore.accessControl.allow_binaries as bin}
          <div class="inline-flex items-center bg-zinc-800/80 border border-zinc-700 px-2 py-1 rounded text-xs font-mono text-zinc-300 space-x-2">
            <span>{bin}</span>
            <button
              onclick={() => handleRemoveBinary(bin)}
              class="text-zinc-500 hover:text-rose-400 transition-colors ml-1"
              title="Remove binary authorization"
            >
              ✕
            </button>
          </div>
        {/each}
      </div>
    </div>

    <!-- Deny Binaries -->
    <div class="bg-zinc-900/40 border border-zinc-800 rounded-lg p-4 space-y-2">
      <div class="text-xs font-mono font-medium text-rose-400">
        ✕ Blocked Binaries (deny_binaries)
      </div>
      <div class="flex flex-wrap gap-2">
        {#each rotationStore.accessControl.deny_binaries as bin}
          <div class="inline-flex items-center bg-rose-950/20 border border-rose-800/40 px-2 py-1 rounded text-xs font-mono text-rose-300">
            <span>{bin}</span>
          </div>
        {/each}
      </div>
    </div>
  </div>
</div>
