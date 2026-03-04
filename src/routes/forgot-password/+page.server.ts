import { fail } from "@sveltejs/kit";
import type { Actions } from "./$types";
import { db } from "$lib/db";
import { users, verificationTokens } from "$lib/schema";
import { eq } from "drizzle-orm";
import { sendPasswordResetEmail } from "$lib/email";
import crypto from "crypto";

export const actions: Actions = {
  default: async ({ request, url }) => {
    const form = await request.formData();
    const email = form.get("email") as string;

    if (!email) {
      return fail(400, { error: "Email is required." });
    }

    const user = await db.query.users.findFirst({
      where: eq(users.email, email),
    });

    // Always show success message (don't reveal if email exists)
    if (!user || !user.password) {
      return { success: true };
    }

    // Delete any existing reset tokens for this email
    await db
      .delete(verificationTokens)
      .where(eq(verificationTokens.email, email));

    // Generate token
    const token = crypto.randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await db.insert(verificationTokens).values({
      email,
      token,
      type: "password_reset",
      expires,
    });

    await sendPasswordResetEmail(email, token, url.origin);

    return { success: true };
  },
};
