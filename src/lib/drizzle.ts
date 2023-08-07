import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import { migrate } from 'drizzle-orm/postgres-js/migrator';
import { env } from '@/lib/env.js';

const connectionString = env.DATABASE_URL;
const client = postgres(connectionString);
export const db = drizzle(client);

await migrate(db, { migrationsFolder: './drizzle' });
