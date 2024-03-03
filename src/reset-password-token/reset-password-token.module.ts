import { Module } from '@nestjs/common';
import { ResetPasswordTokenService } from './reset-password-token.service';
import { ResetPasswordTokenPersistenceModule } from './infrastructure/persistence/presistence.module';

const infrastructurePersistenceModule = ResetPasswordTokenPersistenceModule;

@Module({
  imports: [infrastructurePersistenceModule],
  providers: [ResetPasswordTokenService],
  exports: [ResetPasswordTokenService, ResetPasswordTokenPersistenceModule],
})
export class ResetPasswordTokenModule {}
