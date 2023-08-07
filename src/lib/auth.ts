import { safeParse } from 'valibot';
import { db } from './drizzle.js';
import * as argon2 from 'argon2';

import { Credentials, credentialsSchema } from '@/lib/schemas.js';
import { webcrypto } from 'crypto';
import { Session, User } from './drizzle-schema.js';
import { eq } from 'drizzle-orm';

const signUpNewUserWithCredentials = async (credentials: Credentials) => {
  const credentialsValidation = safeParse(credentialsSchema, credentials);

  if (!credentialsValidation.success) {
    return new Error('Invalid credentials');
  }

  const userLookupBasedOnUsername = await db
    .select()
    .from(User)
    .where(eq(User.username, credentialsValidation.data.username))
    .execute();

  if (userLookupBasedOnUsername) {
    return new Error('User already exists');
  }

  const personalSalt = webcrypto.randomUUID();
  const hashedPassword = await argon2.hash(personalSalt + credentials.password);

  const user = await db
    .insert(User)
    .values({
      username: credentials.username,
      passwordHash: hashedPassword,
      passwordSalt: personalSalt,
      role: 'user',
    })
    .execute();
  return user;
};

const signInUserWithCredentials = async (credentials: Credentials) => {
  const credentialsValidation = safeParse(credentialsSchema, credentials);

  if (!credentialsValidation.success) {
    return new Error('Invalid credentials');
  }

  const userLookupBasedOnUsername = await db
    .select()
    .from(User)
    .where(eq(User.username, credentialsValidation.data.username))
    .execute();

  if (!userLookupBasedOnUsername) {
    return new Error('User does not exist');
  }

  const user = userLookupBasedOnUsername.at(0);

  if (!user) {
    return new Error('User does not exist');
  }

  const usersPersonalSalt = user.passwordSalt;
  const usersHashedPassword = user.passwordHash;
  const passwordsMatch = await argon2.verify(
    usersHashedPassword,
    usersPersonalSalt + credentials.password,
  );

  if (!passwordsMatch) {
    return new Error('Password is incorrect');
  }

  const sessionToken = webcrypto.randomUUID();
  const csrfToken = webcrypto.randomUUID();

  await db.insert(Session).values({
    csrfToken: csrfToken,
    expiresAt: new Date(Date.now() + 1000 * 60 * 60),
    token: sessionToken,
    userid: user.id,
  });

  const session_query = await db
    .select()
    .from(Session)
    .where(eq(Session.token, sessionToken))
    .execute();

  const session = session_query.at(0);
  if (!session) {
    return new Error('Something went wrong with the session creation');
  }
  return session;
};

const signOutUserFromSession = async (
  sessionId: Session['id'],
  csrfToken: Session['csrfToken'],
) => {
  const session_query = await db
    .select()
    .from(Session)
    .where(eq(Session.id, sessionId))
    .execute();
  const session = session_query.at(0);

  if (!session) {
    return new Error('Session does not exist');
  }

  if (session.csrfToken !== csrfToken) {
    return new Error('CSRF tokens do not match');
  }

  const deletedSession = await db
    .delete(Session)
    .where(eq(Session.id, sessionId))
    .execute();

  return deletedSession;
};

const getUserFromSession = async (
  sessionId: Session['id'],
  csrfToken: Session['csrfToken'],
) => {
  const session_query = await db
    .select()
    .from(Session)
    .where(eq(Session.id, sessionId))
    .innerJoin(User, eq(Session.userid, User.id))
    .execute();

  const session = session_query.at(0)?.sessions;
  const user = session_query.at(0)?.users;

  if (!session || !user) {
    return new Error('Session does not exist');
  }

  if (session.expiresAt < new Date()) {
    await db.delete(Session).where(eq(Session.id, session.id)).execute();

    return new Error('Session has expired');
  }

  if (session.csrfToken !== csrfToken) {
    return new Error('CSRF tokens do not match');
  }

  return user;
};

const compareCsrfToken = async (
  sessionToken: Session['token'],
  csrfToken: Session['csrfToken'],
) => {
  const session_query = await db
    .select()
    .from(Session)
    .where(eq(Session.token, sessionToken))
    .execute();
  const session = session_query.at(0);

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
