import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreateVerificationTokenTable1709322745664
  implements MigrationInterface
{
  name = 'CreateVerificationTokenTable1709322745664';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE TABLE "emailVerificationToken" ("id" integer NOT NULL, "email" character varying NOT NULL, "token" integer NOT NULL, "expires" TIMESTAMP NOT NULL, CONSTRAINT "UQ_8ddb6b4f6450c4954b535aa53e9" UNIQUE ("email"), CONSTRAINT "UQ_baaf1bd018a31be76da33390162" UNIQUE ("token"), CONSTRAINT "PK_7612ac3ad105042ff1634696362" PRIMARY KEY ("id"))`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE "emailVerificationToken"`);
  }
}
