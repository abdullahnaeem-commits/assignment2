<script lang="ts">
  let { data, form } = $props();

  let password = $state("");
  let confirmPassword = $state("");
  let showPassword = $state(false);

  const passwordMismatch = $derived(
    confirmPassword.length > 0 && password !== confirmPassword
  );

  const canSubmit = $derived(
    password.length >= 6 && !passwordMismatch && confirmPassword.length > 0
  );
</script>

<div class="min-h-[calc(100vh-56px)] flex items-center justify-center bg-gray-50 px-4">
  <div class="w-full max-w-md bg-white p-8 rounded-2xl shadow-lg">
    {#if !data.valid}
      <div class="text-center">
        <div class="text-red-600 text-lg font-semibold mb-4">Invalid Link</div>
        <p class="text-gray-600 mb-6">{data.error}</p>
        <a
          href="/forgot-password"
          class="inline-block bg-blue-600 hover:bg-blue-700 text-white px-6 py-2.5 rounded-lg transition font-medium"
        >
          Request New Link
        </a>
      </div>
    {:else}
      <h1 class="text-3xl font-bold mb-6 text-center text-gray-900">Reset Password</h1>

      {#if form?.error}
        <div class="mb-4 p-3 bg-red-100 text-red-700 rounded-lg text-sm">
          {form.error}
        </div>
      {/if}

      <form method="POST" class="space-y-4">
        <input type="hidden" name="token" value={data.token} />

        <div>
          <label for="password" class="block text-sm font-medium text-gray-700 mb-1">
            New Password
          </label>
          <div class="relative">
            <input
              id="password"
              name="password"
              type={showPassword ? "text" : "password"}
              required
              minlength="6"
              bind:value={password}
              placeholder="••••••••"
              class="w-full border border-gray-300 p-2.5 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 focus:outline-none pr-16"
            />
            <button
              type="button"
              onclick={() => (showPassword = !showPassword)}
              class="absolute right-3 top-1/2 -translate-y-1/2 text-sm text-gray-500 hover:text-gray-700 font-medium"
            >
              {showPassword ? "Hide" : "Show"}
            </button>
          </div>
          {#if password.length > 0 && password.length < 6}
            <p class="text-red-500 text-xs mt-1">Must be at least 6 characters</p>
          {/if}
        </div>

        <div>
          <label for="confirm" class="block text-sm font-medium text-gray-700 mb-1">
            Confirm Password
          </label>
          <input
            id="confirm"
            type={showPassword ? "text" : "password"}
            required
            minlength="6"
            bind:value={confirmPassword}
            placeholder="••••••••"
            class="w-full border border-gray-300 p-2.5 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 focus:outline-none"
          />
          {#if passwordMismatch}
            <p class="text-red-500 text-xs mt-1">Passwords don't match</p>
          {/if}
        </div>

        <button
          type="submit"
          disabled={!canSubmit}
          class="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 disabled:cursor-not-allowed text-white p-2.5 rounded-lg transition font-medium"
        >
          Reset Password
        </button>
      </form>
    {/if}
  </div>
</div>
