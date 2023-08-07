import { Session, User } from '@/lib/drizzle-schema.js';
import { db } from '@/lib/drizzle.js';
import { logger } from '@/lib/logger.js';
import * as auth from '@/lib/auth.js';
import express, { Router } from 'express';
import { safeParse } from 'valibot';
import { eq } from 'drizzle-orm';

const router = express.Router() as Router;

router.get('/session', async (req, res) => {
  const sessionToken = req?.cookies?.sessionToken;
  if (!sessionToken || typeof sessionToken !== 'string') {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  const session_query = (
    await db
      .select()
      .from(Session)
      .where(eq(Session.token, sessionToken))
      .innerJoin(User, eq(Session.userid, User.id))
      .limit(1)
      .execute()
  ).at(0);

  if (!session_query) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  const session = session_query.sessions;
  const user = session_query.users;

  if (session.expiresAt < new Date()) {
    await db.delete(Session).where(eq(Session.id, session.id)).execute();
    return res.status(301).redirect('login');
  }

  res.setHeader('X-CSRF-Token', session.csrfToken);

  return res.status(200).json({
    user: { username: user.username, role: user.role },
  });
});

router.post('/login', async (req, res) => {
  const credentials = {
    username: req?.body?.username,
    password: req?.body?.password,
  };
  logger.info(credentials.password, credentials.username);

  const result = safeParse(auth.credentialsSchema, credentials);
  if (!result.success) {
    logger.error(result.error);
    return res.status(400).json({ message: 'Invalid username or password' });
  }

  const session = await auth.signInUserWithCredentials({
    username: result.data.username,
    password: result.data.password,
  });

  if (session instanceof Error) {
    logger.error(session.message);
    return res.status(400).json({ message: 'Invalid username or password' });
  }

  res.setHeader('Set-Cookie', [
    `sessionToken=${session.token}; HttpOnly; Path=/; Max-Age=86400; SameSite=Strict`,
  ]);

  res.setHeader('X-CSRF-Token', session.csrfToken);

  return res.status(200).json({ message: 'Successfully logged in' });
});

router.post('/signup', async (req, res) => {
  const credentials = {
    username: req?.body?.username,
    password: req?.body?.password,
  };

  logger.info(credentials.password, credentials.username);

  const result = safeParse(auth.credentialsSchema, credentials);
  if (!result.success) {
    logger.error(result.error.issues[0].input);
    return res.status(400).json({ message: 'Invalid username or password' });
  }

  const userLookupBasedOnUsername = await db
    .select()
    .from(User)
    .where(eq(User.username, credentials.username))
    .execute();

  if (userLookupBasedOnUsername.length > 0) {
    logger.error('User already exists');
    return res.status(400).json({ message: 'User already exists' });
  }

  const newUser = await auth.signUpNewUserWithCredentials({
    username: result.data.username,
    password: result.data.password,
  });
  if (newUser instanceof Error) {
    logger.error(newUser.message);
    return res.status(400).json({ message: newUser.message });
  }

  const session = await auth.signInUserWithCredentials({
    username: result.data.username,
    password: result.data.password,
  });

  if (session instanceof Error) {
    logger.error(session.message);
    return res.status(400).json({ message: session.message });
  }

  logger.success('User created');

  res.setHeader(
    'Set-Cookie',
    `session=${session.token}; Expires=${new Date(
      session.token,
    ).toUTCString()}; HttpOnly; Path=/`,
  );

  res.setHeader('X-CSRF-Token', session.csrfToken);

  return res.redirect(301, '/');
});

router.post('/logout', async (req, res) => {
  const sessionToken = req?.cookies?.sessionToken;
  const csrfToken = req?.headers['X-CSRF-Token'];
  if (!sessionToken) {
    return res.status(400).json({ message: 'No session token provided' });
  }

  if (!csrfToken || typeof csrfToken !== 'string') {
    return res.status(400).json({ message: 'No CSRF token provided' });
  }

  const validCsrfToken = await auth.compareCsrfToken(sessionToken, csrfToken);

  if (!validCsrfToken) {
    return res.status(400).json({ message: 'Invalid CSRF token' });
  }
  await db.delete(Session).where(eq(Session.token, sessionToken)).execute();

  res.setHeader('Set-Cookie', [
    `sessionToken=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict`,
  ]);

  return res.status(200).json({ message: 'Successfully logged out' });
});

export default router;
