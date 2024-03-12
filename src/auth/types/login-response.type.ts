import { User } from 'src/users/domain/user';

export type LoginResponseType = Readonly<{
  token: string;
  tokenExpires: number;
  user: User;
}>;
