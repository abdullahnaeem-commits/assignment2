import {
  pgTable,
  text,
  timestamp,
  uuid,
  integer,
  primaryKey,
} from "drizzle-orm/pg-core";

/* =========================
   USERS
========================= */

export const users = pgTable("user", {
  id: uuid("id").defaultRandom().primaryKey(),

  name: text("name"),
  email: text("email").unique().notNull(),
  emailVerified: timestamp("emailVerified", { mode: "date" }),
  image: text("image"),

  password: text("password"), // only for credentials login
  role: text("role").default("user").notNull(), // "user" | "admin"
  createdAt: timestamp("created_at", { mode: "date" })
    .defaultNow()
    .notNull(),
});

/* =========================
   SESSIONS (Database Strategy)
========================= */

export const sessions = pgTable("session", {
  sessionToken: text("sessionToken").primaryKey(),

  userId: uuid("userId")
    .notNull()
    .references(() => users.id, { onDelete: "cascade" }),

  expires: timestamp("expires", { mode: "date" }).notNull(),
});

/* =========================
   ACCOUNTS (OAuth)
========================= */

export const accounts = pgTable(
  "account",
  {
    userId: uuid("userId")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),

    type: text("type").notNull(),
    provider: text("provider").notNull(),
    providerAccountId: text("providerAccountId").notNull(),

    refresh_token: text("refresh_token"),
    access_token: text("access_token"),
    expires_at: integer("expires_at"),
    token_type: text("token_type"),
    scope: text("scope"),
    id_token: text("id_token"),
    session_state: text("session_state"),
  },
  (account) => ({
    compoundKey: primaryKey({
      columns: [account.provider, account.providerAccountId],
    }),
  })
);

/* =========================
   VERIFICATION TOKENS
========================= */

export const verificationTokens = pgTable("verification_token", {
  id: uuid("id").defaultRandom().primaryKey(),
  email: text("email").notNull(),
  token: text("token").notNull().unique(),
  type: text("type").notNull(), // "email_verification" | "password_reset"
  expires: timestamp("expires", { mode: "date" }).notNull(),
});

/* =========================
   CHAT CONVERSATIONS
========================= */

export const conversations = pgTable("conversation", {
  id: uuid("id").defaultRandom().primaryKey(),
  userId: uuid("userId")
    .notNull()
    .references(() => users.id, { onDelete: "cascade" }),
  title: text("title").notNull().default("New Chat"),
  createdAt: timestamp("created_at", { mode: "date" }).defaultNow().notNull(),
  updatedAt: timestamp("updated_at", { mode: "date" }).defaultNow().notNull(),
});

/* =========================
   CHAT MESSAGES
========================= */

export const chatMessages = pgTable("chat_message", {
  id: uuid("id").defaultRandom().primaryKey(),
  conversationId: uuid("conversationId")
    .notNull()
    .references(() => conversations.id, { onDelete: "cascade" }),
  role: text("role").notNull(), // "user" | "assistant"
  content: text("content").notNull(),
  createdAt: timestamp("created_at", { mode: "date" }).defaultNow().notNull(),
});

/* =========================
   TYPES (IMPORTANT)
========================= */

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;

export type Session = typeof sessions.$inferSelect;
export type Account = typeof accounts.$inferSelect;

export type Conversation = typeof conversations.$inferSelect;
export type ChatMessage = typeof chatMessages.$inferSelect;