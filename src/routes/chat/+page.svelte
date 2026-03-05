<script lang="ts">
  import ChatMessage from "$lib/components/ChatMessage.svelte";
  import ChatInput from "$lib/components/ChatInput.svelte";
  import ChatSidebar from "$lib/components/ChatSidebar.svelte";

  type Message = {
    id: string;
    role: "user" | "assistant";
    content: string;
    position: number;
    branch: string;
    branchGroup: string | null;
    branchIndex: number;
    parentMessageId: string | null;
  };

  type Conversation = { id: string; title: string; updatedAt: string };

  let allMessages: Message[] = $state([]);
  // For each branchGroup, which branchIndex is active
  let activeVersions: Record<string, number> = $state({});
  // The branch we're currently "on" for sending new messages
  let activeBranch = $state("main");

  let input = $state("");
  let isLoading = $state(false);
  let error: string | null = $state(null);
  let chatContainer: HTMLDivElement;

  let conversationsList: Conversation[] = $state([]);
  let activeConversationId: string | null = $state(null);
  let sidebarOpen = $state(false);

  /**
   * Build the visible message list by walking positions and following
   * the active branch at each fork point.
   */
  const visibleMessages = $derived.by(() => {
    if (allMessages.length === 0) return [];

    // Group by position
    const byPos: Record<number, Message[]> = {};
    for (const m of allMessages) {
      if (!byPos[m.position]) byPos[m.position] = [];
      byPos[m.position].push(m);
    }

    const positions = Object.keys(byPos).map(Number).sort((a, b) => a - b);
    const result: Message[] = [];
    let currentBranch = "main";

    for (const pos of positions) {
      const msgs = byPos[pos];

      // Check if this position has a fork (branchGroup)
      const forked = msgs.filter((m) => m.branchGroup);
      if (forked.length > 0) {
        const bg = forked[0].branchGroup!;
        const activeIdx = activeVersions[bg] ?? latestIndex(bg);
        const chosen = forked.find(
          (m) => m.branchGroup === bg && m.branchIndex === activeIdx
        );
        if (chosen) {
          result.push(chosen);
          // Switch current branch to follow the chosen fork
          if (chosen.branchIndex === 0) {
            currentBranch = chosen.branch; // stays "main" for original
          } else {
            currentBranch = chosen.branch; // the branchGroup UUID for edits
          }
        }
      } else {
        // Non-forked position: only show if it belongs to current branch
        const matching = msgs.filter((m) => m.branch === currentBranch);
        if (matching.length > 0) {
          result.push(matching[0]);
        }
      }
    }

    return result;
  });

  function latestIndex(bg: string): number {
    const msgs = allMessages.filter((m) => m.branchGroup === bg);
    return msgs.length > 0 ? Math.max(...msgs.map((m) => m.branchIndex)) : 0;
  }

  function versionCount(bg: string, role: string): number {
    return allMessages.filter((m) => m.branchGroup === bg && m.role === role).length;
  }

  // Derive which branch we're on based on the last visible message
  $effect(() => {
    const vis = visibleMessages;
    if (vis.length > 0) {
      activeBranch = vis[vis.length - 1].branch;
    } else {
      activeBranch = "main";
    }
  });

  $effect(() => {
    loadConversations();
  });

  async function loadConversations() {
    try {
      const res = await fetch("/api/conversations");
      if (res.ok) conversationsList = await res.json();
    } catch { /* ignore */ }
  }

  async function loadConversation(id: string) {
    try {
      const res = await fetch(`/api/conversations/${id}`);
      if (!res.ok) return;
      const data = await res.json();
      activeConversationId = id;
      allMessages = data.messages.map((m: any) => ({
        id: m.id,
        role: m.role,
        content: m.content,
        position: m.position ?? 0,
        branch: m.branch ?? "main",
        branchGroup: m.branchGroup ?? m.branch_group ?? null,
        branchIndex: m.branchIndex ?? m.branch_index ?? 0,
        parentMessageId: m.parentMessageId ?? m.parent_message_id ?? null,
      }));
      activeVersions = {};
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
      if (activeConversationId === id) startNewChat();
    } catch {
      error = "Failed to delete conversation";
    }
  }

  function startNewChat() {
    activeConversationId = null;
    allMessages = [];
    activeVersions = {};
    activeBranch = "main";
    error = null;
    input = "";
    sidebarOpen = false;
  }

  function scrollToBottom() {
    if (chatContainer) {
      setTimeout(() => { chatContainer.scrollTop = chatContainer.scrollHeight; }, 0);
    }
  }

  function handleVersionChange(branchGroup: string, newIndex: number) {
    activeVersions = { ...activeVersions, [branchGroup]: newIndex };
  }

  // === Send a normal new message ===
  async function handleSubmit() {
    if (!input.trim() || isLoading) return;

    const maxPos = allMessages.length > 0
      ? Math.max(...allMessages.map((m) => m.position))
      : -1;

    const tempUser: Message = {
      id: crypto.randomUUID(),
      role: "user",
      content: input.trim(),
      position: maxPos + 1,
      branch: activeBranch,
      branchGroup: null,
      branchIndex: 0,
      parentMessageId: null,
    };

    allMessages = [...allMessages, tempUser];
    const userContent = input.trim();
    input = "";
    isLoading = true;
    error = null;
    scrollToBottom();

    try {
      const contextMsgs = visibleMessages.map((m) => ({
        role: m.role, content: m.content,
      }));

      const response = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          messages: contextMsgs,
          conversationId: activeConversationId,
          currentBranch: activeBranch,
        }),
      });

      if (!response.ok) throw new Error(`Failed (${response.status})`);

      const newConvId = response.headers.get("X-Conversation-Id");
      if (newConvId && !activeConversationId) activeConversationId = newConvId;

      const tempAssistant: Message = {
        id: crypto.randomUUID(),
        role: "assistant",
        content: "",
        position: maxPos + 2,
        branch: activeBranch,
        branchGroup: null,
        branchIndex: 0,
        parentMessageId: tempUser.id,
      };
      allMessages = [...allMessages, tempAssistant];

      await readStream(response, tempAssistant);
      await reloadConversation();
    } catch (e) {
      error = e instanceof Error ? e.message : "Something went wrong";
    } finally {
      isLoading = false;
      scrollToBottom();
    }
  }

  // === Edit a message: fork the conversation ===
  async function handleEdit(msg: Message, newContent: string) {
    isLoading = true;
    error = null;

    // Context = all visible messages before the edit position
    const contextMsgs = visibleMessages
      .filter((m) => m.position < msg.position)
      .map((m) => ({ role: m.role, content: m.content }));

    try {
      const response = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          messages: [...contextMsgs, { role: "user", content: newContent }],
          conversationId: activeConversationId,
          editPosition: msg.position,
          currentBranch: activeBranch,
        }),
      });

      if (!response.ok) throw new Error(`Failed (${response.status})`);

      const branchMetaStr = response.headers.get("X-Branch-Meta");
      let newBranch = activeBranch;
      let branchGroup: string | null = null;
      let branchIndex = 0;
      if (branchMetaStr) {
        const meta = JSON.parse(branchMetaStr);
        branchGroup = meta.branchGroup;
        branchIndex = meta.branchIndex;
        newBranch = meta.branch;
      }

      // Add temp messages for streaming
      const tempUser: Message = {
        id: crypto.randomUUID(),
        role: "user",
        content: newContent,
        position: msg.position,
        branch: newBranch,
        branchGroup,
        branchIndex,
        parentMessageId: null,
      };
      const tempAssistant: Message = {
        id: crypto.randomUUID(),
        role: "assistant",
        content: "",
        position: msg.position + 1,
        branch: newBranch,
        branchGroup,
        branchIndex,
        parentMessageId: tempUser.id,
      };

      allMessages = [...allMessages, tempUser, tempAssistant];
      if (branchGroup) {
        activeVersions = { ...activeVersions, [branchGroup]: branchIndex };
      }

      await readStream(response, tempAssistant);

      // Save the selected version before reload
      const savedVersions = branchGroup
        ? { ...activeVersions, [branchGroup]: branchIndex }
        : { ...activeVersions };

      await reloadConversation();
      activeVersions = savedVersions;
    } catch (e) {
      error = e instanceof Error ? e.message : "Something went wrong";
    } finally {
      isLoading = false;
      scrollToBottom();
    }
  }

  // === Regenerate: re-edit with same content ===
  async function handleRegenerate() {
    const vis = visibleMessages;
    if (vis.length < 2) return;
    const lastAssistant = vis[vis.length - 1];
    const lastUser = vis[vis.length - 2];
    if (lastAssistant.role !== "assistant" || lastUser.role !== "user") return;
    await handleEdit(lastUser, lastUser.content);
  }

  // === Helpers ===
  async function readStream(response: Response, target: Message) {
    const reader = response.body?.getReader();
    if (!reader) throw new Error("No stream");
    const decoder = new TextDecoder();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      target.content += decoder.decode(value, { stream: true });
      allMessages = [...allMessages.slice(0, -1), { ...target }];
      scrollToBottom();
    }
  }

  async function reloadConversation() {
    await loadConversations();
    if (activeConversationId) await loadConversation(activeConversationId);
  }
</script>

<div class="flex h-[calc(100vh-64px)]">
  <button
    onclick={() => (sidebarOpen = !sidebarOpen)}
    class="md:hidden fixed bottom-20 left-3 z-50 bg-gray-900 text-white p-2.5 rounded-full shadow-lg"
    aria-label="Toggle chat history"
  >
    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h7" />
    </svg>
  </button>

  <div class="
    {sidebarOpen ? 'translate-x-0' : '-translate-x-full'}
    md:translate-x-0 transition-transform duration-200
    fixed md:relative z-40 w-64 h-[calc(100vh-64px)] flex-shrink-0
  ">
    <ChatSidebar
      conversations={conversationsList}
      activeId={activeConversationId}
      onselect={loadConversation}
      onnew={startNewChat}
      ondelete={deleteConversation}
    />
  </div>

  {#if sidebarOpen}
    <button
      class="fixed inset-0 bg-black/30 z-30 md:hidden"
      onclick={() => (sidebarOpen = false)}
      aria-label="Close sidebar"
    ></button>
  {/if}

  <div class="flex-1 flex flex-col bg-white min-w-0">
    <div class="border-b border-gray-200 px-4 sm:px-6 py-3 flex items-center justify-between bg-white">
      <div>
        <h1 class="text-lg font-semibold text-gray-900">AI Chat</h1>
        <p class="text-xs text-gray-500">Powered by Google Gemini</p>
      </div>
      {#if visibleMessages.length > 0}
        <button onclick={startNewChat} class="text-sm text-gray-500 hover:text-blue-600 transition px-3 py-1.5 rounded-lg hover:bg-gray-100">
          New Chat
        </button>
      {/if}
    </div>

    <div bind:this={chatContainer} class="flex-1 overflow-y-auto px-4 sm:px-6 py-4">
      {#if visibleMessages.length === 0}
        <div class="flex flex-col items-center justify-center h-full text-center">
          <div class="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mb-4">
            <svg class="w-8 h-8 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
            </svg>
          </div>
          <h2 class="text-xl font-semibold text-gray-900 mb-2">Start a conversation</h2>
          <p class="text-gray-500 text-sm max-w-sm">Ask me anything! I'm powered by Google Gemini and ready to help.</p>
        </div>
      {:else}
        {#each visibleMessages as message, i (message.id)}
          {@const bg = message.branchGroup}
          {@const vc = bg ? versionCount(bg, message.role) : 1}
          {@const cv = bg ? (activeVersions[bg] ?? latestIndex(bg)) : 0}
          <ChatMessage
            role={message.role}
            content={message.content}
            isLast={i === visibleMessages.length - 1}
            {isLoading}
            versionCount={vc}
            currentVersion={cv}
            onversionchange={bg ? (idx) => handleVersionChange(bg, idx) : undefined}
            onedit={message.role === "user" ? (nc) => handleEdit(message, nc) : undefined}
            onregenerate={message.role === "assistant" && i === visibleMessages.length - 1 ? handleRegenerate : undefined}
          />
        {/each}

        {#if isLoading && visibleMessages[visibleMessages.length - 1]?.role === "user"}
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

    <div class="border-t border-gray-200 px-4 sm:px-6 py-3 bg-white">
      <ChatInput bind:value={input} onsubmit={handleSubmit} {isLoading} />
    </div>
  </div>
</div>
