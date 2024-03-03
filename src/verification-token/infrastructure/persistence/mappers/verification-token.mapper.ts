import { VerificationToken } from 'src/verification-token/domain/verification-token';
import { VerificationTokenEntity } from '../entities/verification-token.entity';

export class VerificationTokenMapper {
  static toDomain(raw: VerificationTokenEntity): VerificationToken {
    const verificationToken = new VerificationToken();

    verificationToken.email = raw.email;
    verificationToken.id = raw.id;
    verificationToken.expires = raw.expires;
    verificationToken.token = raw.token;

    return verificationToken;
  }

  static toPersistence(
    verificationToken: VerificationToken,
  ): VerificationTokenEntity {
    const verificationTokenEntity = new VerificationTokenEntity();

    verificationTokenEntity.email = verificationToken.email;
    verificationTokenEntity.expires = verificationToken.expires;
    verificationTokenEntity.id = verificationToken.id;
    verificationTokenEntity.token = verificationToken.token;

    return verificationTokenEntity;
  }
}
