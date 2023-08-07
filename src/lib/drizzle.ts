import { drizzle } from 'drizzle-orm/planetscale-serverless';
import { connect } from '@planetscale/database';
import {
  int,
  mysqlEnum,
  mysqlTable,
  serial,
  timestamp,
  text,
} from 'drizzle-orm/mysql-core';
import { type InferModel } from 'drizzle-orm';
import { env } from './env.js';

export const User = mysqlTable('users', {
  id: serial('id').primaryKey(),
  username: text('username').unique(),
  passwordHash: text('password_hash'),
  passwordSalt: text('password_salt'),
  role: mysqlEnum('role', ['user', 'admin']),
  createdAt: timestamp('created_at').notNull().default(new Date()),
  updatedAt: timestamp('updated_at').notNull().default(new Date()),
});
export type User = InferModel<typeof User>;
export type NewUser = InferModel<typeof User, 'insert'>;
export const Session = mysqlTable('sessions', {
  id: serial('id').primaryKey(),
  token: text('token').unique(),
  csrfToken: text('csrf_token'),
  expiresAt: timestamp('expires_at').notNull(),
  userid: int('user_id').references(() => User.id),
});
export type Session = InferModel<typeof Session>;
export type NewSession = InferModel<typeof Session, 'insert'>;
const connection = connect({
  host: env.DATABASE_HOST,
  username: env.DATABASE_USERNAME,
  password: env.DATABASE_PASSWORD,
});

export const db = drizzle(connection);
