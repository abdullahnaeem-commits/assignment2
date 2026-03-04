import { redirect } from "@sveltejs/kit";
import type { PageServerLoad } from "./$types";
import { db } from "$lib/db";
import { users, verificationTokens } from "$lib/schema";
import { eq, and } from "drizzle-orm";

export const load: PageServerLoad = async ({ url }) => {
  const token = url.searchParams.get("token");

  if (!token) {
    return { error: "Invalid verification link." };
  }

  const record = await db.query.verificationTokens.findFirst({
    where: and(
      eq(verificationTokens.token, token),
      eq(verificationTokens.type, "email_verification")
    ),
  });

  if (!record) {
    return { error: "Invalid or expired verification link." };
  }

  if (record.expires < new Date()) {
    await db
      .delete(verificationTokens)
      .where(eq(verificationTokens.id, record.id));
    return { error: "This verification link has expired. Please register again." };
  }

  // Mark email as verified
  await db
    .update(users)
    .set({ emailVerified: new Date() })
    .where(eq(users.email, record.email));

  // Delete the token
  await db
    .delete(verificationTokens)
    .where(eq(verificationTokens.id, record.id));

  throw redirect(303, "/login?verified=true");
};
