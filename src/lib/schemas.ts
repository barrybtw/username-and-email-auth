import { string, object, minLength, maxLength, type Input } from 'valibot';
export const signInOrUpSchema = object({
  username: string([minLength(3), maxLength(20)]),
  password: string([minLength(8), maxLength(20)]),
});
export type SignInOrUp = Input<typeof signInOrUpSchema>;
