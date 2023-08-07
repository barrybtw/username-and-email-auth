import { type InferModel } from 'drizzle-orm';
import {
  pgTable,
  integer,
  pgEnum,
  serial,
  varchar,
  timestamp,
} from 'drizzle-orm/pg-core';

export const Role = {
  Unknown: 'unknown',
  User: 'user',
  Admin: 'admin',
} as const;
export const RoleEnum = pgEnum('role', ['unknown', 'user', 'admin'] as const);
export const User = pgTable('users', {
  id: serial('id').primaryKey().notNull(),
  username: varchar('username', { length: 191 }).unique().notNull(),
  passwordHash: varchar('password_hash', { length: 191 }).notNull(),
  passwordSalt: varchar('password_salt', { length: 191 }).notNull(),
  role: RoleEnum('user'),
  createdAt: timestamp('created_at').notNull().default(new Date()),
  updatedAt: timestamp('updated_at').notNull().default(new Date()),
});
export type User = InferModel<typeof User>;
export type NewUser = InferModel<typeof User, 'insert'>;

export const Session = pgTable('sessions', {
  id: serial('id').primaryKey(),
  token: varchar('token', { length: 191 }).unique().notNull(),
  csrfToken: varchar('csrf_token', { length: 191 }).notNull(),
  expiresAt: timestamp('expires_at').notNull(),
  userid: integer('user_id')
    .notNull()
    .references(() => User.id),
});

export type Session = InferModel<typeof Session>;
export type NewSession = InferModel<typeof Session, 'insert'>;
