<script lang="ts">
  type Conversation = {
    id: string;
    title: string;
    updatedAt: string;
  };

  let {
    conversations,
    activeId,
    onselect,
    onnew,
    ondelete,
  }: {
    conversations: Conversation[];
    activeId: string | null;
    onselect: (id: string) => void;
    onnew: () => void;
    ondelete: (id: string) => void;
  } = $props();
</script>

<div class="flex flex-col h-full bg-gray-50 border-r border-gray-200">
  <div class="p-3">
    <button
      onclick={onnew}
      class="w-full bg-blue-600 hover:bg-blue-700 text-white px-4 py-2.5 rounded-lg text-sm font-medium transition flex items-center justify-center gap-2"
    >
      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
      </svg>
      New Chat
    </button>
  </div>

  <div class="flex-1 overflow-y-auto px-2 pb-2 space-y-1">
    {#if conversations.length === 0}
      <p class="text-xs text-gray-400 text-center py-4">No conversations yet</p>
    {:else}
      {#each conversations as conv (conv.id)}
        <div class="group relative">
          <button
            onclick={() => onselect(conv.id)}
            class="w-full text-left px-3 py-2.5 rounded-lg text-sm transition truncate {conv.id === activeId
              ? 'bg-blue-100 text-blue-900 font-medium'
              : 'hover:bg-gray-200 text-gray-700'}"
          >
            {conv.title}
          </button>
          <button
            onclick={(e) => { e.stopPropagation(); ondelete(conv.id); }}
            class="absolute right-2 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 text-gray-400 hover:text-red-500 transition p-1"
            title="Delete conversation"
          >
            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
            </svg>
          </button>
        </div>
      {/each}
    {/if}
  </div>
</div>
