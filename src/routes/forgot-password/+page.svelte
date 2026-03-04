<script lang="ts">
  let { form } = $props();
</script>

<div class="min-h-[calc(100vh-56px)] flex items-center justify-center bg-gray-50 px-4">
  <div class="w-full max-w-md bg-white p-8 rounded-2xl shadow-lg">
    <h1 class="text-3xl font-bold mb-2 text-center text-gray-900">Forgot Password</h1>
    <p class="text-gray-600 text-center text-sm mb-6">
      Enter your email and we'll send you a reset link.
    </p>

    {#if form?.success}
      <div class="mb-4 p-4 bg-green-100 text-green-700 rounded-lg text-sm">
        If an account with that email exists, we've sent a password reset link. Check your inbox.
      </div>
    {/if}

    {#if form?.error}
      <div class="mb-4 p-3 bg-red-100 text-red-700 rounded-lg text-sm">
        {form.error}
      </div>
    {/if}

    <form method="POST" class="space-y-4">
      <div>
        <label for="email" class="block text-sm font-medium text-gray-700 mb-1">Email</label>
        <input
          id="email"
          name="email"
          type="email"
          required
          placeholder="you@email.com"
          class="w-full border border-gray-300 p-2.5 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 focus:outline-none"
        />
      </div>

      <button
        type="submit"
        class="w-full bg-blue-600 hover:bg-blue-700 text-white p-2.5 rounded-lg transition font-medium"
      >
        Send Reset Link
      </button>
    </form>

    <p class="mt-6 text-center text-sm text-gray-600">
      Remember your password?
      <a href="/login" class="text-blue-600 hover:underline font-medium">Sign in</a>
    </p>
  </div>
</div>
