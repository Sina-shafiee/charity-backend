import { User } from 'src/users/domain/user';

export type LoginResponseType = Readonly<
  User & {
    token: string;
    tokenExpires: number;
  }
>;
