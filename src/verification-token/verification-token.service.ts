import { VerificationTokenRepository } from './infrastructure/persistence/repositories/verification-token.repository';
import { Injectable } from '@nestjs/common';
import { VerificationToken } from './domain/verification-token';
import { EntityCondition } from 'src/utils/types/entity-condition.type';
import { NullableType } from 'src/utils/types/nullable.type';

@Injectable()
export class VerificationTokenService {
  constructor(
    private readonly verificationTokenRepository: VerificationTokenRepository,
  ) {}
  async create(
    data: Omit<VerificationToken, 'id'>,
  ): Promise<VerificationToken> {
    const isAlreadyExist = await this.verificationTokenRepository.findOne({
      email: data.email,
    });

    if (isAlreadyExist) {
      await this.verificationTokenRepository.deleteByEmail(data.email);
    }

    return this.verificationTokenRepository.create(data as VerificationToken);
  }
  async findOne(
    options: EntityCondition<VerificationToken>,
  ): Promise<NullableType<VerificationToken>> {
    return this.verificationTokenRepository.findOne(options);
  }

  async delete(email: string): Promise<void> {
    return this.verificationTokenRepository.deleteByEmail(email);
  }
}
