import { safeParse } from 'valibot';
import { prisma } from './database.js';
import * as argon2 from 'argon2';

import { Credentials, credentialsSchema } from '@/lib/schemas.js';
import { Session } from '@prisma/client';
import { webcrypto } from 'crypto';

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

  const personalSalt = webcrypto.randomUUID();
  const hashedPassword = await argon2.hash(personalSalt + credentials.password);

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
  const passwordsMatch = await argon2.verify(
    usersHashedPassword,
    usersPersonalSalt + credentials.password,
  );

  if (!passwordsMatch) {
    return new Error('Password is incorrect');
  }

  const sessionToken = webcrypto.randomUUID();
  const csrfToken = webcrypto.randomUUID();

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

const signOutUserFromSession = async (
  sessionId: Session['id'],
  csrfToken: Session['csrfToken'],
) => {
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

const getUserFromSession = async (
  sessionId: Session['id'],
  csrfToken: Session['csrfToken'],
) => {
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

  if (session.expiresAt < new Date()) {
    await prisma.session.delete({
      where: {
        id: session.id,
      },
    });
    return new Error('Session has expired');
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
