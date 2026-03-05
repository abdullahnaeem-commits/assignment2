<script lang="ts">
  import { signOut } from "@auth/sveltekit/client";
  import favicon from "$lib/assets/favicon.svg";
  import "../app.css";

  let { children, data } = $props();
  const session = $derived(data.session);
  let mobileMenuOpen = $state(false);
</script>

<svelte:head>
  <link rel="icon" href={favicon} />
</svelte:head>

<nav class="bg-gray-900 text-white shadow-lg">
  <div class="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between">
    <a href="/" class="text-xl font-bold tracking-tight hover:text-gray-200 transition">
      AuthApp
    </a>

    <!-- Desktop nav -->
    <div class="hidden md:flex items-center gap-4">
      {#if session?.user}
        <a href="/dashboard" class="text-sm hover:text-gray-300 transition">Dashboard</a>
        <a href="/chat" class="text-sm hover:text-gray-300 transition">Chat</a>
        <a href="/profile" class="text-sm hover:text-gray-300 transition">Profile</a>
        {#if (session as any)?.role === "admin"}
          <a href="/admin" class="text-sm text-yellow-400 hover:text-yellow-300 transition font-medium">Admin</a>
        {/if}
        <span class="text-sm text-gray-400">
          {session.user.name || session.user.email}
        </span>
        <button
          onclick={() => signOut({ redirectTo: "/" })}
          class="bg-red-600 hover:bg-red-700 px-3 py-1.5 rounded-lg text-sm font-medium transition"
        >
          Logout
        </button>
      {:else}
        <a href="/login" class="text-sm hover:text-gray-300 transition">Login</a>
        <a
          href="/register"
          class="bg-blue-600 hover:bg-blue-700 px-3 py-1.5 rounded-lg text-sm font-medium transition"
        >
          Register
        </a>
      {/if}
    </div>

    <!-- Mobile hamburger -->
    <button
      class="md:hidden p-2 rounded-lg hover:bg-gray-800 transition"
      onclick={() => (mobileMenuOpen = !mobileMenuOpen)}
      aria-label="Toggle menu"
    >
      {#if mobileMenuOpen}
        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
        </svg>
      {:else}
        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
        </svg>
      {/if}
    </button>
  </div>

  <!-- Mobile menu -->
  {#if mobileMenuOpen}
    <div class="md:hidden border-t border-gray-800 px-4 py-3 space-y-2">
      {#if session?.user}
        <div class="text-sm text-gray-400 pb-2 border-b border-gray-800">
          {session.user.name || session.user.email}
        </div>
        <a href="/dashboard" class="block py-2 text-sm hover:text-gray-300 transition" onclick={() => (mobileMenuOpen = false)}>Dashboard</a>
        <a href="/chat" class="block py-2 text-sm hover:text-gray-300 transition" onclick={() => (mobileMenuOpen = false)}>Chat</a>
        <a href="/profile" class="block py-2 text-sm hover:text-gray-300 transition" onclick={() => (mobileMenuOpen = false)}>Profile</a>
        {#if (session as any)?.role === "admin"}
          <a href="/admin" class="block py-2 text-sm text-yellow-400 hover:text-yellow-300 transition font-medium" onclick={() => (mobileMenuOpen = false)}>Admin</a>
        {/if}
        <button
          onclick={() => { mobileMenuOpen = false; signOut({ redirectTo: "/" }); }}
          class="w-full mt-2 bg-red-600 hover:bg-red-700 px-3 py-2 rounded-lg text-sm font-medium transition text-left"
        >
          Logout
        </button>
      {:else}
        <a href="/login" class="block py-2 text-sm hover:text-gray-300 transition" onclick={() => (mobileMenuOpen = false)}>Login</a>
        <a
          href="/register"
          class="block mt-1 bg-blue-600 hover:bg-blue-700 px-3 py-2 rounded-lg text-sm font-medium transition text-center"
          onclick={() => (mobileMenuOpen = false)}
        >
          Register
        </a>
      {/if}
    </div>
  {/if}
</nav>

<main>
  {@render children()}
</main>
