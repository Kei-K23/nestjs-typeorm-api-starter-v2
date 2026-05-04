import { MigrationInterface, QueryRunner } from "typeorm";

export class AddLastLogoutField1777882141920 implements MigrationInterface {
    name = 'AddLastLogoutField1777882141920'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "users" ADD "lastLogoutAt" TIMESTAMP`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "lastLogoutAt"`);
    }

}
