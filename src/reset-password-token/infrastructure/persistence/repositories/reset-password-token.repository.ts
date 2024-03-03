import { FindOptionsWhere, Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { ResetPasswordToken } from 'src/reset-password-token/domain/reset-password-token';
import { ResetPasswordTokenEntity } from '../entities/reset-password-token.entity';
import { ResetPasswordTokenMapper } from '../mappers/reset-password-token.mapper';
import { EntityCondition } from 'src/utils/types/entity-condition.type';

export class ResetPasswordTokenRepository {
  constructor(
    @InjectRepository(ResetPasswordTokenEntity)
    private readonly resetPasswordRepository: Repository<ResetPasswordTokenEntity>,
  ) {}
  async create(data: ResetPasswordToken): Promise<ResetPasswordToken> {
    const persistenceModel = ResetPasswordTokenMapper.toPersistence(data);
    return this.resetPasswordRepository.save(
      this.resetPasswordRepository.create(persistenceModel),
    );
  }

  async findOne(
    options: EntityCondition<ResetPasswordToken>,
  ): Promise<ResetPasswordToken | null> {
    const entity = await this.resetPasswordRepository.findOne({
      where: options as FindOptionsWhere<ResetPasswordToken>,
    });
    return entity ? ResetPasswordTokenMapper.toDomain(entity) : null;
  }

  async deleteByEmail(email: ResetPasswordToken['email']): Promise<void> {
    await this.resetPasswordRepository.delete({
      email,
    });
  }
}
