<script lang="ts">
  let { data, form } = $props();
</script>

<div class="min-h-[calc(100vh-56px)] bg-gray-50 p-6 sm:p-8">
  <div class="max-w-6xl mx-auto">
    <h1 class="text-3xl font-bold text-gray-900 mb-2">Admin Dashboard</h1>
    <p class="text-gray-600 mb-8">Manage users and view analytics</p>

    {#if form?.error}
      <div class="mb-4 p-3 bg-red-100 text-red-700 rounded-lg text-sm">
        {form.error}
      </div>
    {/if}

    {#if form?.success}
      <div class="mb-4 p-3 bg-green-100 text-green-700 rounded-lg text-sm">
        Action completed successfully.
      </div>
    {/if}

    <!-- Stats Cards -->
    <div class="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
      <div class="bg-white p-5 rounded-2xl shadow">
        <div class="text-sm text-gray-500">Total Users</div>
        <div class="text-3xl font-bold text-gray-900">{data.stats.total}</div>
      </div>
      <div class="bg-white p-5 rounded-2xl shadow">
        <div class="text-sm text-gray-500">Admins</div>
        <div class="text-3xl font-bold text-blue-600">{data.stats.admins}</div>
      </div>
      <div class="bg-white p-5 rounded-2xl shadow">
        <div class="text-sm text-gray-500">Verified</div>
        <div class="text-3xl font-bold text-green-600">{data.stats.verified}</div>
      </div>
      <div class="bg-white p-5 rounded-2xl shadow">
        <div class="text-sm text-gray-500">Unverified</div>
        <div class="text-3xl font-bold text-orange-500">{data.stats.unverified}</div>
      </div>
    </div>

    <!-- Users Table -->
    <div class="bg-white rounded-2xl shadow overflow-hidden">
      <div class="p-5 border-b border-gray-200">
        <h2 class="text-lg font-semibold text-gray-900">All Users</h2>
      </div>

      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead class="bg-gray-50 text-gray-600">
            <tr>
              <th class="text-left p-4 font-medium">Name</th>
              <th class="text-left p-4 font-medium">Email</th>
              <th class="text-left p-4 font-medium">Role</th>
              <th class="text-left p-4 font-medium">Verified</th>
              <th class="text-left p-4 font-medium">Joined</th>
              <th class="text-left p-4 font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            {#each data.users as user}
              <tr class="border-t border-gray-100 hover:bg-gray-50">
                <td class="p-4 text-gray-900 font-medium">
                  {user.name || "—"}
                </td>
                <td class="p-4 text-gray-600">{user.email}</td>
                <td class="p-4">
                  <span
                    class="inline-block px-2.5 py-0.5 rounded-full text-xs font-medium {user.role === 'admin'
                      ? 'bg-blue-100 text-blue-700'
                      : 'bg-gray-100 text-gray-600'}"
                  >
                    {user.role}
                  </span>
                </td>
                <td class="p-4">
                  {#if user.emailVerified}
                    <span class="text-green-600 text-xs font-medium">Verified</span>
                  {:else}
                    <span class="text-orange-500 text-xs font-medium">Unverified</span>
                  {/if}
                </td>
                <td class="p-4 text-gray-500">
                  {new Date(user.createdAt).toLocaleDateString("en-US", {
                    month: "short",
                    day: "numeric",
                    year: "numeric",
                  })}
                </td>
                <td class="p-4">
                  <div class="flex gap-2">
                    <form method="POST" action="?/toggleRole">
                      <input type="hidden" name="userId" value={user.id} />
                      <button
                        type="submit"
                        class="text-xs px-2.5 py-1 rounded-lg border border-blue-300 text-blue-600 hover:bg-blue-50 transition"
                      >
                        {user.role === "admin" ? "Demote" : "Promote"}
                      </button>
                    </form>
                    <form
                      method="POST"
                      action="?/deleteUser"
                      onsubmit={(e) => {
                        if (!confirm(`Delete ${user.email}?`)) e.preventDefault();
                      }}
                    >
                      <input type="hidden" name="userId" value={user.id} />
                      <button
                        type="submit"
                        class="text-xs px-2.5 py-1 rounded-lg border border-red-300 text-red-600 hover:bg-red-50 transition"
                      >
                        Delete
                      </button>
                    </form>
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div>
