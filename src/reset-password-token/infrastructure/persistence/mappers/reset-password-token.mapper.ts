import { VerificationToken } from 'src/verification-token/domain/verification-token';
import { ResetPasswordTokenEntity } from '../entities/reset-password-token.entity';

export class ResetPasswordTokenMapper {
  static toDomain(raw: ResetPasswordTokenEntity): VerificationToken {
    const verificationToken = new VerificationToken();

    verificationToken.email = raw.email;
    verificationToken.id = raw.id;
    verificationToken.expires = raw.expires;
    verificationToken.token = raw.token;

    return verificationToken;
  }

  static toPersistence(
    verificationToken: VerificationToken,
  ): ResetPasswordTokenEntity {
    const verificationTokenEntity = new ResetPasswordTokenEntity();

    verificationTokenEntity.email = verificationToken.email;
    verificationTokenEntity.expires = verificationToken.expires;
    verificationTokenEntity.id = verificationToken.id;
    verificationTokenEntity.token = verificationToken.token;

    return verificationTokenEntity;
  }
}
