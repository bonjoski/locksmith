<script lang="ts">
  interface Props {
    status: string;
    label?: string;
  }

  let { status, label }: Props = $props();

  let badgeClasses = $derived.by(() => {
    switch (status) {
      case "GRANTED":
      case "StatusValid":
      case "ONLINE":
      case "ACTIVE":
      case "valid":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
      case "DENIED":
      case "StatusExpired":
      case "OFFLINE":
      case "expired":
        return "bg-rose-500/10 text-rose-400 border-rose-500/30";
      case "CHALLENGE_REQUIRED":
      case "StatusExpiring":
      case "expiring":
        return "bg-amber-500/10 text-amber-400 border-amber-500/30";
      case "REVOKED":
      case "revoked":
        return "bg-zinc-800 text-zinc-400 border-zinc-700";
      default:
        return "bg-cyan-500/10 text-cyan-400 border-cyan-500/30";
    }
  });

  let displayLabel = $derived(label ?? status.replace("Status", ""));
</script>

<span
  class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-mono font-medium border {badgeClasses}"
>
  <span class="w-1.5 h-1.5 rounded-full mr-1.5 {status === 'GRANTED' || status === 'StatusValid' || status === 'ONLINE' ? 'bg-emerald-400' : status === 'DENIED' || status === 'StatusExpired' ? 'bg-rose-400' : status === 'REVOKED' ? 'bg-zinc-500' : 'bg-amber-400'}"></span>
  {displayLabel}
</span>
