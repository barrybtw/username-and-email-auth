import { prisma } from './database.js';
import bcrypt from 'bcrypt';
// Assume you already have the Database class with delete, update, and create methods for UserAccount and Session

const auth = {
  async signUpNewUser(username: string, password: string) {
    const userLookupByUsername = await prisma.user.findUnique({
      where: {
        username: username,
      },
    });

    if (userLookupByUsername) {
      return new Error('User already exists');
    }

    const personalSalt = await bcrypt.genSalt(20);
    const hashedPassword = await bcrypt.hash(personalSalt + password, 20);

    const user = await prisma.user.create({
      data: {
        username: username,
        passwordHash: hashedPassword,
        passwordSalt: personalSalt,
      },
    });

    return user;
  },

  async signInWithCredentials(username: string, password: string) {
    const userLookupByUsername = await prisma.user.findUnique({
      where: {
        username: username,
      },
    });

    if (!userLookupByUsername) {
      return new Error('User does not exist');
    }

    const usersPersonalSalt = userLookupByUsername.passwordSalt;
    const usersHashedPassword = userLookupByUsername.passwordHash;
    const passwordsMatch = await bcrypt.compare(
      usersPersonalSalt + password,
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
  },
  async signOutUser(sessionId: number) {
    const session = await prisma.session.delete({
      where: {
        id: sessionId,
      },
    });

    return session;
  },
  async getUserFromSession(sessionId: number) {
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

    return session.user;
  },
  async compareCsrfToken(sessionId: number, csrfToken: string) {
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

    return true;
  },
};

export default auth;
