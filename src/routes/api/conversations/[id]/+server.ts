import { db } from "$lib/db";
import { conversations, chatMessages } from "$lib/schema";
import { eq, and, asc } from "drizzle-orm";
import { json } from "@sveltejs/kit";
import type { RequestHandler } from "./$types";

// GET: Load messages for a specific conversation (with version data)
export const GET: RequestHandler = async ({ params, locals }) => {
  const session = await locals.auth();
  if (!session?.user?.id) {
    return new Response("Unauthorized", { status: 401 });
  }

  const [conv] = await db
    .select()
    .from(conversations)
    .where(
      and(
        eq(conversations.id, params.id),
        eq(conversations.userId, session.user.id)
      )
    );

  if (!conv) {
    return new Response("Not found", { status: 404 });
  }

  const allMessages = await db
    .select()
    .from(chatMessages)
    .where(eq(chatMessages.conversationId, params.id))
    .orderBy(asc(chatMessages.position), asc(chatMessages.branchIndex));

  return json({ conversation: conv, messages: allMessages });
};
