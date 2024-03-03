import { FindOptionsWhere, Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { VerificationToken } from 'src/verification-token/domain/verification-token';
import { VerificationTokenEntity } from '../entities/verification-token.entity';
import { VerificationTokenMapper } from '../mappers/verification-token.mapper';
import { EntityCondition } from 'src/utils/types/entity-condition.type';

export class VerificationTokenRepository {
  constructor(
    @InjectRepository(VerificationTokenEntity)
    private readonly verificationTokenRepository: Repository<VerificationTokenEntity>,
  ) {}
  async create(data: VerificationToken): Promise<VerificationToken> {
    const persistenceModel = VerificationTokenMapper.toPersistence(data);
    return this.verificationTokenRepository.save(
      this.verificationTokenRepository.create(persistenceModel),
    );
  }

  async findOne(
    options: EntityCondition<VerificationToken>,
  ): Promise<VerificationToken | null> {
    const entity = await this.verificationTokenRepository.findOne({
      where: options as FindOptionsWhere<VerificationToken>,
    });
    return entity ? VerificationTokenMapper.toDomain(entity) : null;
  }

  async deleteByEmail(email: VerificationToken['email']): Promise<void> {
    await this.verificationTokenRepository.delete({
      email,
    });
  }
}
