import { db } from "$lib/db";
import { users, verificationTokens } from "$lib/schema";
import bcrypt from "bcrypt";
import crypto from "crypto";
import { fail, redirect } from "@sveltejs/kit";
import type { Actions } from "./$types";
import { sendVerificationEmail } from "$lib/email";
import { eq } from "drizzle-orm";

export const actions: Actions = {
  default: async ({ request, url }) => {
    const form = await request.formData();
    const name = form.get("name") as string;
    const email = form.get("email") as string;
    const password = form.get("password") as string;

    if (!email || !password) {
      return fail(400, { error: "Email and password are required." });
    }

    if (password.length < 6) {
      return fail(400, { error: "Password must be at least 6 characters." });
    }

    // Step 1: Check if email already exists
    const existing = await db.query.users.findFirst({
      where: eq(users.email, email),
    });

    if (existing) {
      return fail(400, { error: "An account with this email already exists." });
    }

    // Step 2: Create user
    try {
      const hashed = await bcrypt.hash(password, 12);

      await db.insert(users).values({
        name,
        email,
        password: hashed,
      });
    } catch {
      return fail(500, { error: "Registration failed. Please try again." });
    }

    // Step 2: Generate verification token
    const token = crypto.randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    await db.insert(verificationTokens).values({
      email,
      token,
      type: "email_verification",
      expires,
    });

    // Step 3: Send verification email (don't block registration if this fails)
    try {
      await sendVerificationEmail(email, token, url.origin);
    } catch {
      // Email failed but account was created - user can request a new verification email later
    }

    throw redirect(303, "/login?registered=true");
  },
};
