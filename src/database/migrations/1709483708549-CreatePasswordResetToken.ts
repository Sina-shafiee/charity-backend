import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreatePasswordResetToken1709483708549
  implements MigrationInterface
{
  name = 'CreatePasswordResetToken1709483708549';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE TABLE "resetPasswordToken" ("id" SERIAL NOT NULL, "email" character varying NOT NULL, "token" integer NOT NULL, "expires" TIMESTAMP NOT NULL, CONSTRAINT "UQ_93b8b2609c61c911402f71d44b4" UNIQUE ("email"), CONSTRAINT "UQ_46d06b136da21abbfd9a510932c" UNIQUE ("token"), CONSTRAINT "PK_be3bedae1bb733f73acfe3d5481" PRIMARY KEY ("id"))`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE "resetPasswordToken"`);
  }
}
