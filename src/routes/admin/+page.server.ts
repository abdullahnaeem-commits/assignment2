import { redirect, fail } from "@sveltejs/kit";
import type { PageServerLoad, Actions } from "./$types";
import { db } from "$lib/db";
import { users } from "$lib/schema";
import { eq, count, sql } from "drizzle-orm";

export const load: PageServerLoad = async (event) => {
  const session = await event.locals.auth();

  if (!session?.user) {
    throw redirect(303, "/login");
  }

  // Check admin role
  const currentUser = await db.query.users.findFirst({
    where: eq(users.id, session.user.id!),
  });

  if (!currentUser || currentUser.role !== "admin") {
    throw redirect(303, "/dashboard");
  }

  // Get all users
  const allUsers = await db
    .select({
      id: users.id,
      name: users.name,
      email: users.email,
      role: users.role,
      emailVerified: users.emailVerified,
      createdAt: users.createdAt,
    })
    .from(users)
    .orderBy(users.createdAt);

  // Analytics
  const [totalResult] = await db.select({ count: count() }).from(users);
  const [adminResult] = await db
    .select({ count: count() })
    .from(users)
    .where(eq(users.role, "admin"));
  const [verifiedResult] = await db
    .select({ count: count() })
    .from(users)
    .where(sql`${users.emailVerified} IS NOT NULL`);

  return {
    users: allUsers.map((u) => ({
      ...u,
      emailVerified: u.emailVerified?.toISOString() ?? null,
      createdAt: u.createdAt.toISOString(),
    })),
    stats: {
      total: totalResult.count,
      admins: adminResult.count,
      verified: verifiedResult.count,
      unverified: totalResult.count - verifiedResult.count,
    },
  };
};

export const actions: Actions = {
  toggleRole: async ({ request, locals }) => {
    const session = await locals.auth();
    if (!session?.user) throw redirect(303, "/login");

    const admin = await db.query.users.findFirst({
      where: eq(users.id, session.user.id!),
    });
    if (!admin || admin.role !== "admin") {
      return fail(403, { error: "Unauthorized." });
    }

    const form = await request.formData();
    const userId = form.get("userId") as string;

    if (userId === session.user.id) {
      return fail(400, { error: "You cannot change your own role." });
    }

    const target = await db.query.users.findFirst({
      where: eq(users.id, userId),
    });

    if (!target) return fail(404, { error: "User not found." });

    const newRole = target.role === "admin" ? "user" : "admin";

    await db.update(users).set({ role: newRole }).where(eq(users.id, userId));

    return { success: true };
  },

  deleteUser: async ({ request, locals }) => {
    const session = await locals.auth();
    if (!session?.user) throw redirect(303, "/login");

    const admin = await db.query.users.findFirst({
      where: eq(users.id, session.user.id!),
    });
    if (!admin || admin.role !== "admin") {
      return fail(403, { error: "Unauthorized." });
    }

    const form = await request.formData();
    const userId = form.get("userId") as string;

    if (userId === session.user.id) {
      return fail(400, { error: "You cannot delete your own account." });
    }

    await db.delete(users).where(eq(users.id, userId));

    return { success: true };
  },
};
