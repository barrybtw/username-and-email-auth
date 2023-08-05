import express from 'express';
import { signInOrUpSchema } from '@/lib/schemas.js';
import { safeParse } from 'valibot';
import { logger } from '../lib/logger.js';
import { DB } from '@/lib/db.js';

const router = express.Router();

router.post('/signup', (req, res) => {
  const credentials = {
    username: req.body?.username,
    password: req.body?.password,
  };

  logger.info(credentials.password, credentials.username);

  const result = safeParse(signInOrUpSchema, credentials);
  if (!result.success) {
    logger.error(result.error.issues[0].input);
    return res.status(400).json({ message: 'Invalid username or password' });
  }

  const userAlreadyExists = DB.users.find(
    (user) => user.username === result.data.username,
  );
  if (userAlreadyExists) {
    logger.error('User already exists');
    return res.status(400).json({ message: 'User already exists' });
  }

  const hashedPassword = 'hash' + result.data.password;

  DB.users.push({
    passwordHash: hashedPassword,
    username: result.data.username,
  });

  logger.success('User created');

  const session = {
    id: Math.random() * 10000000,
    username: result.data.username,
    expires: Date.now() + 1000 * 60 * 60 * 24,
    created: Date.now(),
  };

  DB.sessions.push(session);

  res.setHeader(
    'Set-Cookie',
    `session=${session.id}; Expires=${new Date(
      session.expires,
    ).toUTCString()}; HttpOnly; Path=/`,
  );

  return res.redirect(301, '/');
});

export default router;
