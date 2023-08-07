/**
 * IDEA
 *
 * 1. User can create an account /auth/signup
 * 2. User can login /auth/login
 *
 */
import express from 'express';
import router from '@/routes/auth.js';
import { logger } from '@/lib/logger.js';
import { prisma } from '@/lib/database.js';

async function main() {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  app.use('/auth', router);

  app.use((req, res, next) => {
    if (process.env.NODE_ENV != 'development' && !req.secure) {
      return res.redirect('https://' + req.headers.host + req.url);
    }

    next();
  });

  app.listen(3000, () => {
    logger.success('Server is running on port 3000');
  });
}

main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (e) => {
    logger.error(e);
    await prisma.$disconnect();
    process.exit(1);
  })
  .finally(() => {
    logger.info('Goodnight!');
  });
