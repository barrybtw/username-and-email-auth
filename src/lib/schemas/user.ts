import {
  int,
  mysqlEnum,
  mysqlTable,
  serial,
  timestamp,
  text,
} from 'drizzle-orm/mysql-core';

export const User = mysqlTable('users', {
  id: serial('id').primaryKey(),
  username: text('username').unique(),
  passwordHash: text('password_hash'),
  passwordSalt: text('password_salt'),
  role: mysqlEnum('role', ['user', 'admin']),
  createdAt: timestamp('created_at').notNull().default(new Date()),
  updatedAt: timestamp('updated_at').notNull().default(new Date()),
});
export const Session = mysqlTable('sessions', {
  id: serial('id').primaryKey(),
  token: text('token').unique(),
  csrfToken: text('csrf_token'),
  expiresAt: timestamp('expires_at').notNull(),
  userid: int('user_id').references(() => User.id),
});
