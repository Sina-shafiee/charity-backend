import { Module } from '@nestjs/common';
import { ResetPasswordTokenRepository } from './repositories/reset-password-token.repository';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ResetPasswordTokenEntity } from './entities/reset-password-token.entity';

@Module({
  imports: [TypeOrmModule.forFeature([ResetPasswordTokenEntity])],
  providers: [ResetPasswordTokenRepository],
  exports: [ResetPasswordTokenRepository],
})
export class ResetPasswordTokenPersistenceModule {}
