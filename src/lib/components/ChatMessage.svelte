<script lang="ts">
  let { role, content }: { role: string; content: string } = $props();
  const isUser = $derived(role === "user");
</script>

<div class="flex {isUser ? 'justify-end' : 'justify-start'} mb-4">
  <div
    class="max-w-[80%] sm:max-w-[70%] px-4 py-3 rounded-2xl {isUser
      ? 'bg-blue-600 text-white rounded-br-md'
      : 'bg-gray-100 text-gray-900 rounded-bl-md'}"
  >
    {#if !isUser}
      <div class="text-xs font-semibold text-blue-600 mb-1">AI Assistant</div>
    {/if}
    <div class="text-sm leading-relaxed whitespace-pre-wrap">{content}</div>
  </div>
</div>
