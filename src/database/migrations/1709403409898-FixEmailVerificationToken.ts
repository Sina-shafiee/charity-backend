import { MigrationInterface, QueryRunner } from 'typeorm';

export class FixEmailVerificationToken1709403409898
  implements MigrationInterface
{
  name = 'FixEmailVerificationToken1709403409898';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE SEQUENCE IF NOT EXISTS "emailVerificationToken_id_seq" OWNED BY "emailVerificationToken"."id"`,
    );
    await queryRunner.query(
      `ALTER TABLE "emailVerificationToken" ALTER COLUMN "id" SET DEFAULT nextval('"emailVerificationToken_id_seq"')`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "emailVerificationToken" ALTER COLUMN "id" DROP DEFAULT`,
    );
    await queryRunner.query(`DROP SEQUENCE "emailVerificationToken_id_seq"`);
  }
}
