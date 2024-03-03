import { Module } from '@nestjs/common';
import { VerificationTokenService } from './verification-token.service';
import { VerificationTokenPersistenceModule } from './infrastructure/persistence/presistence.module';

const infrastructurePersistenceModule = VerificationTokenPersistenceModule;

@Module({
  imports: [infrastructurePersistenceModule],
  providers: [VerificationTokenService],
  exports: [VerificationTokenService, VerificationTokenPersistenceModule],
})
export class VerificationTokenModule {}
