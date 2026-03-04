import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import * as schema from "./schema";
import { DATABASE_URL } from "$env/static/private";

const pool = new Pool({
  connectionString: DATABASE_URL,
});

export const db = drizzle(pool, {
  schema,
  logger: false,
});

export type DB = typeof db;
