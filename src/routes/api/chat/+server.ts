import { createGoogleGenerativeAI } from "@ai-sdk/google";
import { streamText } from "ai";
import { GEMINI_API_KEY } from "$env/static/private";
import { db } from "$lib/db";
import { conversations, chatMessages } from "$lib/schema";
import { eq, asc, gt } from "drizzle-orm";
import type { RequestHandler } from "./$types";

const google = createGoogleGenerativeAI({
  apiKey: GEMINI_API_KEY,
});

export const POST: RequestHandler = async ({ request, locals }) => {
  try {
    const session = await locals.auth();
    if (!session?.user?.id) {
      return new Response("Unauthorized", { status: 401 });
    }

    const { messages, conversationId, editIndex, regenerate } = await request.json();

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
      await db
        .update(conversations)
        .set({ updatedAt: new Date() })
        .where(eq(conversations.id, convId));
    }

    // Handle edit: delete messages from edit point onward, then save the edited message
    if (editIndex !== undefined && convId) {
      const existingMessages = await db
        .select()
        .from(chatMessages)
        .where(eq(chatMessages.conversationId, convId))
        .orderBy(asc(chatMessages.createdAt));

      if (existingMessages[editIndex]) {
        // Delete this message and all after it
        const cutoffTime = existingMessages[editIndex].createdAt;
        await db
          .delete(chatMessages)
          .where(
            eq(chatMessages.conversationId, convId)
          );
        // Re-insert only the messages before the edit point
        const keepMessages = existingMessages.slice(0, editIndex);
        for (const msg of keepMessages) {
          await db.insert(chatMessages).values({
            conversationId: convId,
            role: msg.role,
            content: msg.content,
          });
        }
      }

      // Save the edited user message
      const lastUserMessage = messages[messages.length - 1];
      if (lastUserMessage?.role === "user") {
        await db.insert(chatMessages).values({
          conversationId: convId,
          role: "user",
          content: lastUserMessage.content,
        });
      }
    }
    // Handle regenerate: delete the last assistant message
    else if (regenerate && convId) {
      const existingMessages = await db
        .select()
        .from(chatMessages)
        .where(eq(chatMessages.conversationId, convId))
        .orderBy(asc(chatMessages.createdAt));

      const lastMsg = existingMessages[existingMessages.length - 1];
      if (lastMsg?.role === "assistant") {
        await db.delete(chatMessages).where(eq(chatMessages.id, lastMsg.id));
      }
    }
    // Normal new message: just save the user message
    else {
      const lastUserMessage = messages[messages.length - 1];
      if (lastUserMessage?.role === "user") {
        await db.insert(chatMessages).values({
          conversationId: convId,
          role: "user",
          content: lastUserMessage.content,
        });
      }
    }

    const result = streamText({
      model: google("gemini-2.5-flash"),
      system: "You are a helpful AI assistant. Be concise and clear in your responses.",
      messages,
      async onFinish({ text }) {
        await db.insert(chatMessages).values({
          conversationId: convId,
          role: "assistant",
          content: text,
        });
      },
    });

    return createTextStreamResponse(result, convId);
  } catch (err) {
    console.error("Chat API error:", err);
    const message = err instanceof Error ? err.message : "Internal server error";
    return new Response(JSON.stringify({ error: message }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
};

function createTextStreamResponse(result: ReturnType<typeof streamText>, convId: string) {
  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      try {
        for await (const chunk of result.textStream) {
          controller.enqueue(encoder.encode(chunk));
        }
        controller.close();
      } catch (err) {
        controller.error(err);
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Transfer-Encoding": "chunked",
      "X-Conversation-Id": convId,
    },
  });
}
