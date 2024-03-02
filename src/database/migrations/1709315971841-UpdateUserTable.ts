import { MigrationInterface, QueryRunner } from 'typeorm';

export class UpdateUserTable1709315971841 implements MigrationInterface {
  name = 'UpdateUserTable1709315971841';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "user" ADD "emailVerified" TIMESTAMP`);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "user" DROP COLUMN "emailVerified"`);
  }
}
