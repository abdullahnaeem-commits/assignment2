<script lang="ts">
  let { data } = $props();
</script>

<div class="min-h-[calc(100vh-56px)] flex items-center justify-center bg-gray-50 px-4">
  <div class="w-full max-w-md bg-white p-8 rounded-2xl shadow-lg text-center">
    {#if data.error}
      <div class="text-red-600 text-lg font-semibold mb-4">Verification Failed</div>
      <p class="text-gray-600 mb-6">{data.error}</p>
      <a
        href="/register"
        class="inline-block bg-blue-600 hover:bg-blue-700 text-white px-6 py-2.5 rounded-lg transition font-medium"
      >
        Register Again
      </a>
    {/if}
  </div>
</div>
