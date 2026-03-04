import { fail, redirect } from "@sveltejs/kit";
import type { PageServerLoad, Actions } from "./$types";
import { db } from "$lib/db";
import { users, verificationTokens } from "$lib/schema";
import { eq, and } from "drizzle-orm";
import bcrypt from "bcrypt";

export const load: PageServerLoad = async ({ url }) => {
  const token = url.searchParams.get("token");

  if (!token) {
    return { error: "Invalid reset link.", valid: false };
  }

  const record = await db.query.verificationTokens.findFirst({
    where: and(
      eq(verificationTokens.token, token),
      eq(verificationTokens.type, "password_reset")
    ),
  });

  if (!record) {
    return { error: "Invalid or expired reset link.", valid: false };
  }

  if (record.expires < new Date()) {
    await db
      .delete(verificationTokens)
      .where(eq(verificationTokens.id, record.id));
    return { error: "This reset link has expired. Please request a new one.", valid: false };
  }

  return { valid: true, token };
};

export const actions: Actions = {
  default: async ({ request }) => {
    const form = await request.formData();
    const token = form.get("token") as string;
    const password = form.get("password") as string;

    if (!token || !password) {
      return fail(400, { error: "Missing required fields." });
    }

    if (password.length < 6) {
      return fail(400, { error: "Password must be at least 6 characters." });
    }

    const record = await db.query.verificationTokens.findFirst({
      where: and(
        eq(verificationTokens.token, token),
        eq(verificationTokens.type, "password_reset")
      ),
    });

    if (!record || record.expires < new Date()) {
      return fail(400, { error: "Invalid or expired reset link." });
    }

    const hashed = await bcrypt.hash(password, 12);

    await db
      .update(users)
      .set({ password: hashed })
      .where(eq(users.email, record.email));

    // Delete the token
    await db
      .delete(verificationTokens)
      .where(eq(verificationTokens.id, record.id));

    throw redirect(303, "/login?reset=true");
  },
};
