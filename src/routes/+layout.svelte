<script lang="ts">
  import { signOut } from "@auth/sveltekit/client";
  import favicon from "$lib/assets/favicon.svg";
  import "../app.css";

  let { children, data } = $props();
  const session = $derived(data.session);
</script>

<svelte:head>
  <link rel="icon" href={favicon} />
</svelte:head>

<nav class="bg-gray-900 text-white shadow-lg">
  <div class="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between">
    <a href="/" class="text-xl font-bold tracking-tight hover:text-gray-200 transition">
      AuthApp
    </a>

    <div class="flex items-center gap-4">
      {#if session?.user}
        <a href="/dashboard" class="text-sm hover:text-gray-300 transition">Dashboard</a>
        <a href="/profile" class="text-sm hover:text-gray-300 transition">Profile</a>
        {#if (session as any)?.role === "admin"}
          <a href="/admin" class="text-sm text-yellow-400 hover:text-yellow-300 transition font-medium">Admin</a>
        {/if}
        <span class="text-sm text-gray-400 hidden sm:inline">
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
  </div>
</nav>

<main>
  {@render children()}
</main>
