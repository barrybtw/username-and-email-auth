import { User, db } from '@/lib/drizzle.js';
import { logger } from '@/lib/logger.js';
import * as auth from '@/lib/auth.js';
import express, { Router } from 'express';
import { safeParse } from 'valibot';

const router = express.Router() as Router;

router.get('/session', async (req, res) => {
  const sessionToken = req?.cookies?.sessionToken;
  if (!sessionToken || typeof sessionToken !== 'string') {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  // const session = await db.query
  const session = await db.select().from(User);

  if (!session) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  if (session.expiresAt < new Date()) {
    await prisma.session.delete({
      where: {
        id: session.id,
      },
    });
    return res.status(301).redirect('login');
  }

  res.setHeader('X-CSRF-Token', session.csrfToken);

  return res.status(200).json({
    user: { username: session.user.username, role: session.user.role },
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

  const userLookupBasedOnUsername = await prisma.user.findFirst({
    where: {
      username: result.data.username,
    },
  });
  if (userLookupBasedOnUsername) {
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

  await prisma.session.delete({
    where: {
      id: sessionToken,
    },
  });

  res.setHeader('Set-Cookie', [
    `sessionToken=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict`,
  ]);

  return res.status(200).json({ message: 'Successfully logged out' });
});

export default router;
