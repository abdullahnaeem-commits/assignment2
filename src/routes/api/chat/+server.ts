import { createGoogleGenerativeAI } from "@ai-sdk/google";
import { streamText } from "ai";
import { GEMINI_API_KEY } from "$env/static/private";
import { db } from "$lib/db";
import { conversations, chatMessages } from "$lib/schema";
import { eq } from "drizzle-orm";
import type { RequestHandler } from "./$types";

const google = createGoogleGenerativeAI({
  apiKey: GEMINI_API_KEY,
});

export const POST: RequestHandler = async ({ request, locals }) => {
  const session = await locals.auth();
  if (!session?.user?.id) {
    return new Response("Unauthorized", { status: 401 });
  }

  const { messages, conversationId } = await request.json();

  // Get or create conversation
  let convId = conversationId;
  if (!convId) {
    const firstMessage = messages[0]?.content || "New Chat";
    const title = firstMessage.slice(0, 100);
    const [conv] = await db
      .insert(conversations)
      .values({ userId: session.user.id, title })
      .returning();
    convId = conv.id;
  } else {
    // Update the conversation timestamp
    await db
      .update(conversations)
      .set({ updatedAt: new Date() })
      .where(eq(conversations.id, convId));
  }

  // Save user message
  const lastUserMessage = messages[messages.length - 1];
  if (lastUserMessage?.role === "user") {
    await db.insert(chatMessages).values({
      conversationId: convId,
      role: "user",
      content: lastUserMessage.content,
    });
  }

  const result = streamText({
    model: google("gemini-2.0-flash"),
    system: "You are a helpful AI assistant. Be concise and clear in your responses.",
    messages,
    async onFinish({ text }) {
      // Save assistant response to database
      await db.insert(chatMessages).values({
        conversationId: convId,
        role: "assistant",
        content: text,
      });
    },
  });

  return result.toDataStreamResponse({
    headers: { "X-Conversation-Id": convId },
  });
};
