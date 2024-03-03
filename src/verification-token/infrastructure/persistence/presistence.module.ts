import { Module } from '@nestjs/common';
import { VerificationTokenRepository } from './repositories/verification-token.repository';
import { TypeOrmModule } from '@nestjs/typeorm';
import { VerificationTokenEntity } from './entities/verification-token.entity';

@Module({
  imports: [TypeOrmModule.forFeature([VerificationTokenEntity])],
  providers: [VerificationTokenRepository],
  exports: [VerificationTokenRepository],
})
export class VerificationTokenPersistenceModule {}
