import chalk from 'chalk';

export const logger = {
  info: (...message: unknown[]) => console.log(chalk.blue(...message)),
  warn: (...message: unknown[]) => console.log(chalk.yellow(...message)),
  error: (...message: unknown[]) => console.log(chalk.red(...message)),
  success: (...message: unknown[]) => console.log(chalk.green(...message)),
};
