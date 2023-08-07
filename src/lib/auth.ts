import { safeParse } from 'valibot';
import { prisma } from './database.js';
import bcrypt from 'bcrypt';
import { Credentials, credentialsSchema } from '@/lib/schemas.js';
import { Session } from '@prisma/client';

const signUpNewUserWithCredentials = async (credentials: Credentials) => {
  const credentialsValidation = safeParse(credentialsSchema, credentials);

  if (!credentialsValidation.success) {
    return new Error('Invalid credentials');
  }

  const userLookupByUsername = await prisma.user.findUnique({
    where: {
      username: credentials.username,
    },
  });

  if (userLookupByUsername) {
    return new Error('User already exists');
  }

  const personalSalt = await bcrypt.genSalt(20);
  const hashedPassword = await bcrypt.hash(
    personalSalt + credentials.password,
    20,
  );

  const user = await prisma.user.create({
    data: {
      username: credentials.username,
      passwordHash: hashedPassword,
      passwordSalt: personalSalt,
    },
  });

  return user;
};

const signInUserWithCredentials = async (credentials: Credentials) => {
  const credentialsValidation = safeParse(credentialsSchema, credentials);

  if (!credentialsValidation.success) {
    return new Error('Invalid credentials');
  }

  const userLookupByUsername = await prisma.user.findUnique({
    where: {
      username: credentials.username,
    },
  });

  if (!userLookupByUsername) {
    return new Error('User does not exist');
  }

  const usersPersonalSalt = userLookupByUsername.passwordSalt;
  const usersHashedPassword = userLookupByUsername.passwordHash;
  const passwordsMatch = await bcrypt.compare(
    usersPersonalSalt + credentials.password,
    usersHashedPassword,
  );

  if (!passwordsMatch) {
    return new Error('Password is incorrect');
  }

  const sessionToken = await bcrypt.genSalt(20);
  const csrfToken = await bcrypt.genSalt(20);

  const session = await prisma.session.create({
    data: {
      user: {
        connect: {
          id: userLookupByUsername.id,
        },
      },
      token: sessionToken,
      csrfToken: csrfToken,
      expiresAt: new Date(Date.now() + 1000 * 60 * 60),
    },
  });

  return session;
};

const signOutUserFromSession = async (sessionId: number, csrfToken: string) => {
  const session = await prisma.session.findUnique({
    where: {
      id: sessionId,
    },
  });

  if (!session) {
    return new Error('Session does not exist');
  }

  if (session.csrfToken !== csrfToken) {
    return new Error('CSRF tokens do not match');
  }

  const deletedSession = await prisma.session.delete({
    where: {
      id: sessionId,
    },
  });

  return deletedSession;
};

const getUserFromSession = async (sessionId: number, csrfToken: string) => {
  const session = await prisma.session.findUnique({
    where: {
      id: sessionId,
    },
    include: {
      user: true,
    },
  });

  if (!session) {
    return new Error('Session does not exist');
  }

  if (session.csrfToken !== csrfToken) {
    return new Error('CSRF tokens do not match');
  }

  return session.user;
};

const compareCsrfToken = async (
  sessionToken: Session['token'],
  csrfToken: Session['csrfToken'],
) => {
  const session = await prisma.session.findUnique({
    where: {
      token: sessionToken,
    },
  });

  if (!session) {
    return false;
  }

  return session.csrfToken === csrfToken;
};

export {
  credentialsSchema,
  signUpNewUserWithCredentials,
  getUserFromSession,
  signInUserWithCredentials,
  signOutUserFromSession,
  compareCsrfToken,
};
