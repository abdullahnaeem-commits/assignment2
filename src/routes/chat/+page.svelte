<script lang="ts">
  import ChatMessage from "$lib/components/ChatMessage.svelte";
  import ChatInput from "$lib/components/ChatInput.svelte";
  import ChatSidebar from "$lib/components/ChatSidebar.svelte";

  type Message = {
    id: string;
    role: "user" | "assistant";
    content: string;
  };

  type Conversation = {
    id: string;
    title: string;
    updatedAt: string;
  };

  let messages: Message[] = $state([]);
  let input = $state("");
  let isLoading = $state(false);
  let error: string | null = $state(null);
  let chatContainer: HTMLDivElement;

  let conversationsList: Conversation[] = $state([]);
  let activeConversationId: string | null = $state(null);
  let sidebarOpen = $state(false);

  // Load conversations on mount
  $effect(() => {
    loadConversations();
  });

  async function loadConversations() {
    try {
      const res = await fetch("/api/conversations");
      if (res.ok) {
        conversationsList = await res.json();
      }
    } catch {
      // silently fail
    }
  }

  async function loadConversation(id: string) {
    try {
      const res = await fetch(`/api/conversations/${id}`);
      if (!res.ok) return;

      const data = await res.json();
      activeConversationId = id;
      messages = data.messages.map((m: any) => ({
        id: m.id,
        role: m.role,
        content: m.content,
      }));
      error = null;
      sidebarOpen = false;
      scrollToBottom();
    } catch {
      error = "Failed to load conversation";
    }
  }

  async function deleteConversation(id: string) {
    try {
      await fetch("/api/conversations", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ conversationId: id }),
      });
      conversationsList = conversationsList.filter((c) => c.id !== id);
      if (activeConversationId === id) {
        activeConversationId = null;
        messages = [];
      }
    } catch {
      error = "Failed to delete conversation";
    }
  }

  function startNewChat() {
    activeConversationId = null;
    messages = [];
    error = null;
    input = "";
    sidebarOpen = false;
  }

  function scrollToBottom() {
    if (chatContainer) {
      setTimeout(() => {
        chatContainer.scrollTop = chatContainer.scrollHeight;
      }, 0);
    }
  }

  async function handleSubmit() {
    if (!input.trim() || isLoading) return;

    const userMessage: Message = {
      id: crypto.randomUUID(),
      role: "user",
      content: input.trim(),
    };

    messages = [...messages, userMessage];
    const currentInput = input;
    input = "";
    isLoading = true;
    error = null;
    scrollToBottom();

    try {
      const response = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          messages: messages.map((m) => ({ role: m.role, content: m.content })),
          conversationId: activeConversationId,
        }),
      });

      if (!response.ok) {
        throw new Error(`Failed to get response (${response.status})`);
      }

      // Capture the conversation ID from the response
      const newConvId = response.headers.get("X-Conversation-Id");
      if (newConvId && !activeConversationId) {
        activeConversationId = newConvId;
      }

      const reader = response.body?.getReader();
      if (!reader) throw new Error("No response stream");

      const assistantMessage: Message = {
        id: crypto.randomUUID(),
        role: "assistant",
        content: "",
      };
      messages = [...messages, assistantMessage];

      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          if (line.startsWith("0:")) {
            try {
              const text = JSON.parse(line.slice(2));
              assistantMessage.content += text;
              messages = [...messages.slice(0, -1), { ...assistantMessage }];
              scrollToBottom();
            } catch {
              // skip non-text chunks
            }
          }
        }
      }

      // Refresh conversation list
      await loadConversations();
    } catch (e) {
      error = e instanceof Error ? e.message : "Something went wrong";
      if (messages.length > 0 && messages[messages.length - 1].role === "user") {
        input = currentInput;
      }
    } finally {
      isLoading = false;
      scrollToBottom();
    }
  }
</script>

<div class="flex h-[calc(100vh-64px)]">
  <!-- Mobile sidebar toggle -->
  <button
    onclick={() => (sidebarOpen = !sidebarOpen)}
    class="md:hidden fixed bottom-20 left-3 z-50 bg-gray-900 text-white p-2.5 rounded-full shadow-lg"
    aria-label="Toggle chat history"
  >
    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h7" />
    </svg>
  </button>

  <!-- Sidebar -->
  <div
    class="
      {sidebarOpen ? 'translate-x-0' : '-translate-x-full'}
      md:translate-x-0 transition-transform duration-200
      fixed md:relative z-40
      w-64 h-[calc(100vh-64px)]
      flex-shrink-0
    "
  >
    <ChatSidebar
      conversations={conversationsList}
      activeId={activeConversationId}
      onselect={loadConversation}
      onnew={startNewChat}
      ondelete={deleteConversation}
    />
  </div>

  <!-- Overlay for mobile -->
  {#if sidebarOpen}
    <button
      class="fixed inset-0 bg-black/30 z-30 md:hidden"
      onclick={() => (sidebarOpen = false)}
      aria-label="Close sidebar"
    ></button>
  {/if}

  <!-- Chat area -->
  <div class="flex-1 flex flex-col bg-white min-w-0">
    <!-- Header -->
    <div class="border-b border-gray-200 px-4 sm:px-6 py-3 flex items-center justify-between bg-white">
      <div>
        <h1 class="text-lg font-semibold text-gray-900">AI Chat</h1>
        <p class="text-xs text-gray-500">Powered by Google Gemini</p>
      </div>
      {#if messages.length > 0}
        <button
          onclick={startNewChat}
          class="text-sm text-gray-500 hover:text-blue-600 transition px-3 py-1.5 rounded-lg hover:bg-gray-100"
        >
          New Chat
        </button>
      {/if}
    </div>

    <!-- Messages -->
    <div
      bind:this={chatContainer}
      class="flex-1 overflow-y-auto px-4 sm:px-6 py-4"
    >
      {#if messages.length === 0}
        <div class="flex flex-col items-center justify-center h-full text-center">
          <div class="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mb-4">
            <svg class="w-8 h-8 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
            </svg>
          </div>
          <h2 class="text-xl font-semibold text-gray-900 mb-2">Start a conversation</h2>
          <p class="text-gray-500 text-sm max-w-sm">
            Ask me anything! I'm powered by Google Gemini and ready to help.
          </p>
        </div>
      {:else}
        {#each messages as message (message.id)}
          <ChatMessage role={message.role} content={message.content} />
        {/each}

        {#if isLoading && messages[messages.length - 1]?.role === "user"}
          <div class="flex justify-start mb-4">
            <div class="bg-gray-100 rounded-2xl rounded-bl-md px-4 py-3">
              <div class="flex items-center gap-1">
                <div class="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style="animation-delay: 0ms"></div>
                <div class="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style="animation-delay: 150ms"></div>
                <div class="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style="animation-delay: 300ms"></div>
              </div>
            </div>
          </div>
        {/if}
      {/if}
    </div>

    <!-- Error -->
    {#if error}
      <div class="mx-4 sm:mx-6 mb-2 bg-red-50 border border-red-200 text-red-700 px-4 py-2 rounded-lg text-sm flex items-center justify-between">
        <span>{error}</span>
        <button onclick={() => (error = null)} class="text-red-500 hover:text-red-700 ml-2">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>
    {/if}

    <!-- Input -->
    <div class="border-t border-gray-200 px-4 sm:px-6 py-3 bg-white">
      <ChatInput bind:value={input} onsubmit={handleSubmit} {isLoading} />
    </div>
  </div>
</div>
