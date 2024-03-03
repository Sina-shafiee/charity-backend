import { Injectable } from '@nestjs/common';
import { NullableType } from 'src/utils/types/nullable.type';
import { ResetPasswordToken } from './domain/reset-password-token';
import { EntityCondition } from 'src/utils/types/entity-condition.type';
import { ResetPasswordTokenRepository } from './infrastructure/persistence/repositories/reset-password-token.repository';

@Injectable()
export class ResetPasswordTokenService {
  constructor(
    private readonly verificationTokenRepository: ResetPasswordTokenRepository,
  ) {}
  async create(
    data: Omit<ResetPasswordToken, 'id'>,
  ): Promise<ResetPasswordToken> {
    const isAlreadyExist = await this.verificationTokenRepository.findOne({
      email: data.email,
    });

    if (isAlreadyExist) {
      await this.verificationTokenRepository.deleteByEmail(data.email);
    }

    return this.verificationTokenRepository.create(data as ResetPasswordToken);
  }
  async findOne(
    options: EntityCondition<ResetPasswordToken>,
  ): Promise<NullableType<ResetPasswordToken>> {
    return this.verificationTokenRepository.findOne(options);
  }

  async delete(email: string): Promise<void> {
    return this.verificationTokenRepository.deleteByEmail(email);
  }
}
