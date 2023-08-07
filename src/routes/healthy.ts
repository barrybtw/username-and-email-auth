import { Session, User } from '../lib/drizzle-schema.js';
import { db } from '../lib/drizzle.js';
import express from 'express';

const healthyRouter = express.Router();

healthyRouter.get('/', async (_, res) => {
  const insertUser = await db
    .insert(User)
    .values({
      passwordHash: 'testing123',
      passwordSalt: 'verygoodsalt',
      username: 'testuser' + Math.random() * 500,
      role: 'user',
    })
    .returning()
    .execute();
  const queryAllUsers = await db.select().from(User).execute();
  const queryAllSessions = await db.select().from(Session).execute();
  res.status(200).json({
    message: 'Healthy',
    users: queryAllUsers,
    sessions: queryAllSessions,
    testInsert: insertUser,
  });
});

export default healthyRouter;
