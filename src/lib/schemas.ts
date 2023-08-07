import { string, object, minLength, maxLength, type Output } from 'valibot';
export const credentialsSchema = object({
  username: string([minLength(3), maxLength(20)]),
  password: string([minLength(8), maxLength(20)]),
});
export type Credentials = Output<typeof credentialsSchema>;
