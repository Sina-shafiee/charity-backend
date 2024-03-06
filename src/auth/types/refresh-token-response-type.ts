export type RefreshTokenResponseType = Readonly<{
  token: string;
  refreshToken: string;
  tokenExpires: number;
}>;
