import { MigrationInterface, QueryRunner } from "typeorm";

export class Init1778107037358 implements MigrationInterface {
    name = 'Init1778107037358'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE "modules" ("id" uuid NOT NULL, "createdAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "updatedAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "deletedAt" TIMESTAMP WITH TIME ZONE, "name" character varying NOT NULL, "code" character varying NOT NULL, "allowedActions" text NOT NULL DEFAULT 'CREATE,READ,UPDATE,DELETE', "parentId" uuid, CONSTRAINT "UQ_25b42b11ac8b697cdb2eddcef1a" UNIQUE ("code"), CONSTRAINT "PK_7dbefd488bd96c5bf31f0ce0c95" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE INDEX "IDX_4fc2237062f5e034c8f0537af4" ON "modules" ("deletedAt") `);
        await queryRunner.query(`CREATE TABLE "permissions" ("id" uuid NOT NULL, "createdAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "updatedAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "deletedAt" TIMESTAMP WITH TIME ZONE, "moduleId" uuid NOT NULL, "action" character varying NOT NULL, CONSTRAINT "PK_920331560282b8bd21bb02290df" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE INDEX "IDX_7a0dec7dfde2c5c743fdadf9ba" ON "permissions" ("deletedAt") `);
        await queryRunner.query(`CREATE UNIQUE INDEX "IDX_d08be7a97addd61b394eba245c" ON "permissions" ("moduleId", "action") `);
        await queryRunner.query(`CREATE TABLE "role_permissions" ("roleId" uuid NOT NULL, "permissionId" uuid NOT NULL, CONSTRAINT "PK_d430a02aad006d8a70f3acd7d03" PRIMARY KEY ("roleId", "permissionId"))`);
        await queryRunner.query(`CREATE UNIQUE INDEX "IDX_d430a02aad006d8a70f3acd7d0" ON "role_permissions" ("roleId", "permissionId") `);
        await queryRunner.query(`CREATE TABLE "roles" ("id" uuid NOT NULL, "createdAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "updatedAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "deletedAt" TIMESTAMP WITH TIME ZONE, "name" character varying NOT NULL, "description" character varying, CONSTRAINT "PK_c1433d71a4838793a49dcad46ab" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE INDEX "IDX_e72912af85f8ca6ac65522f71e" ON "roles" ("deletedAt") `);
        await queryRunner.query(`CREATE TABLE "admins" ("id" uuid NOT NULL, "createdAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "updatedAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "deletedAt" TIMESTAMP WITH TIME ZONE, "fullName" character varying NOT NULL, "password" character varying, "email" character varying NOT NULL, "profileImageUrl" character varying, "roleId" uuid NOT NULL, "isBanned" boolean NOT NULL DEFAULT false, "twoFactorEnabled" boolean NOT NULL DEFAULT false, "lastLoginAt" TIMESTAMP WITH TIME ZONE, "lastLogoutAt" TIMESTAMP WITH TIME ZONE, CONSTRAINT "UQ_051db7d37d478a69a7432df1479" UNIQUE ("email"), CONSTRAINT "PK_e3b38270c97a854c48d2e80874e" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE INDEX "IDX_6c06ce78e9eb2b8fed71a5c752" ON "admins" ("deletedAt") `);
        await queryRunner.query(`CREATE INDEX "IDX_20f7eaea0ee98f1484256e59fd" ON "admins" ("fullName") `);
        await queryRunner.query(`CREATE INDEX "IDX_aa69cff29dbc09a27c6b75addf" ON "admins" ("isBanned") `);
        await queryRunner.query(`CREATE TABLE "refresh_tokens" ("id" uuid NOT NULL, "createdAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "updatedAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "token" character varying NOT NULL, "userId" uuid, "adminId" uuid, "expiresAt" TIMESTAMP WITH TIME ZONE, "isRevoked" boolean NOT NULL DEFAULT false, CONSTRAINT "PK_7d8bee0204106019488c4c50ffa" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE TYPE "public"."cache_keys_status_enum" AS ENUM('PENDING', 'VERIFIED', 'EXPIRED', 'USED')`);
        await queryRunner.query(`CREATE TYPE "public"."cache_keys_service_enum" AS ENUM('TWO_FACTOR', 'RESET_PASSWORD')`);
        await queryRunner.query(`CREATE TABLE "cache_keys" ("id" uuid NOT NULL, "createdAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "updatedAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "userId" uuid, "adminId" uuid, "status" "public"."cache_keys_status_enum" NOT NULL DEFAULT 'PENDING', "service" "public"."cache_keys_service_enum" NOT NULL, "code" character varying NOT NULL, "expiresAt" TIMESTAMP WITH TIME ZONE NOT NULL, "requestId" character varying, "attempts" integer NOT NULL DEFAULT '0', "maxAttempts" integer NOT NULL DEFAULT '3', CONSTRAINT "PK_29788e563146dc5caf0f160b8b0" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE TYPE "public"."users_registrationstage_enum" AS ENUM('OTP_VERIFY', 'PASSWORD_SETUP', 'ACCOUNT_SETUP')`);
        await queryRunner.query(`CREATE TABLE "users" ("id" uuid NOT NULL, "createdAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "updatedAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "deletedAt" TIMESTAMP WITH TIME ZONE, "email" character varying, "fullName" character varying, "phone" character varying NOT NULL, "password" character varying, "isBanned" boolean NOT NULL DEFAULT false, "profileImageUrl" character varying, "dateOfBirth" character varying, "gender" character varying, "preferLanguage" character varying, "registrationStage" "public"."users_registrationstage_enum" DEFAULT 'OTP_VERIFY', "fcmToken" character varying, "lastLoginAt" TIMESTAMP WITH TIME ZONE, "lastLogoutAt" TIMESTAMP WITH TIME ZONE, "googleId" character varying, "appleId" character varying, "loginProvider" character varying, CONSTRAINT "PK_a3ffb1c0c8416b9fc6f907b7433" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE INDEX "IDX_2a32f641edba1d0f973c19cc94" ON "users" ("deletedAt") `);
        await queryRunner.query(`CREATE INDEX "IDX_97672ac88f789774dd47f7c8be" ON "users" ("email") `);
        await queryRunner.query(`CREATE INDEX "IDX_4b2bf18167e94dce386d714c67" ON "users" ("fullName") `);
        await queryRunner.query(`CREATE INDEX "IDX_836026b660a661f0dbdc467bf1" ON "users" ("isBanned") `);
        await queryRunner.query(`CREATE TABLE "settings" ("id" uuid NOT NULL, "createdAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "updatedAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "deletedAt" TIMESTAMP WITH TIME ZONE, "key" character varying NOT NULL, "value" character varying DEFAULT '', CONSTRAINT "UQ_c8639b7626fa94ba8265628f214" UNIQUE ("key"), CONSTRAINT "PK_0669fe20e252eb692bf4d344975" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE INDEX "IDX_b8ad02e0a2d004844b17af5e3f" ON "settings" ("deletedAt") `);
        await queryRunner.query(`CREATE TYPE "public"."audit_logs_action_enum" AS ENUM('LOGIN', 'LOGOUT', 'REGISTER', 'UPDATE_PROFILE', 'CHANGE_PASSWORD', 'FORGOT_PASSWORD_OTP', 'RESET_PASSWORD', 'ENABLE_TWO_FACTOR', 'DISABLE_TWO_FACTOR', 'VERIFY_TWO_FACTOR', 'DELETE_ACCOUNT', 'CREATE', 'UPDATE', 'DELETE')`);
        await queryRunner.query(`CREATE TYPE "public"."audit_logs_status_enum" AS ENUM('SUCCESS', 'FAILURE')`);
        await queryRunner.query(`CREATE TABLE "audit_logs" ("id" SERIAL NOT NULL, "adminId" uuid, "action" "public"."audit_logs_action_enum" NOT NULL, "description" text NOT NULL, "entityName" character varying, "entityId" character varying, "oldValue" json, "newValue" json, "ipAddress" character varying, "userAgent" character varying, "device" character varying, "browser" character varying, "os" character varying, "location" character varying, "status" "public"."audit_logs_status_enum" NOT NULL DEFAULT 'SUCCESS', "metadata" json, "createdAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), CONSTRAINT "PK_1bb179d048bbc581caa3b013439" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE INDEX "IDX_2a495f3f3adbd1ceba0346ba16" ON "audit_logs" ("adminId", "action", "createdAt") `);
        await queryRunner.query(`CREATE TYPE "public"."activity_logs_action_enum" AS ENUM('LOGIN', 'LOGOUT', 'REGISTER', 'UPDATE_PROFILE', 'CHANGE_PASSWORD', 'FORGOT_PASSWORD_OTP', 'RESET_PASSWORD', 'ENABLE_TWO_FACTOR', 'DISABLE_TWO_FACTOR', 'VERIFY_TWO_FACTOR', 'DELETE_ACCOUNT', 'CREATE', 'UPDATE', 'DELETE')`);
        await queryRunner.query(`CREATE TYPE "public"."activity_logs_status_enum" AS ENUM('SUCCESS', 'FAILURE')`);
        await queryRunner.query(`CREATE TABLE "activity_logs" ("id" SERIAL NOT NULL, "userId" uuid NOT NULL, "action" "public"."activity_logs_action_enum" NOT NULL, "description" text NOT NULL, "resourceType" character varying, "resourceId" character varying, "ipAddress" character varying, "userAgent" character varying, "device" character varying, "browser" character varying, "os" character varying, "location" character varying, "status" "public"."activity_logs_status_enum" NOT NULL DEFAULT 'SUCCESS', "metadata" json, "createdAt" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), CONSTRAINT "PK_f25287b6140c5ba18d38776a796" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE INDEX "IDX_b5fa115e88e67d287ba7a40223" ON "activity_logs" ("userId", "action", "createdAt") `);
        await queryRunner.query(`ALTER TABLE "modules" ADD CONSTRAINT "FK_a6637494664d871968306442f3b" FOREIGN KEY ("parentId") REFERENCES "modules"("id") ON DELETE SET NULL ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "permissions" ADD CONSTRAINT "FK_e61928198c29bb2202922b08755" FOREIGN KEY ("moduleId") REFERENCES "modules"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "role_permissions" ADD CONSTRAINT "FK_b4599f8b8f548d35850afa2d12c" FOREIGN KEY ("roleId") REFERENCES "roles"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "role_permissions" ADD CONSTRAINT "FK_06792d0c62ce6b0203c03643cdd" FOREIGN KEY ("permissionId") REFERENCES "permissions"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "admins" ADD CONSTRAINT "FK_d27f7a7f01967e4a5e8ba73ebb0" FOREIGN KEY ("roleId") REFERENCES "roles"("id") ON DELETE RESTRICT ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "refresh_tokens" ADD CONSTRAINT "FK_610102b60fea1455310ccd299de" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "refresh_tokens" ADD CONSTRAINT "FK_766ab81fa68d15204df19f83370" FOREIGN KEY ("adminId") REFERENCES "admins"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "cache_keys" ADD CONSTRAINT "FK_534d75a310fe04d609f01d05898" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE NO ACTION ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "cache_keys" ADD CONSTRAINT "FK_dea5419efccb62518e66a63b4d8" FOREIGN KEY ("adminId") REFERENCES "admins"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "audit_logs" ADD CONSTRAINT "FK_9d53d8c4d4227c02e4476129d25" FOREIGN KEY ("adminId") REFERENCES "admins"("id") ON DELETE SET NULL ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "activity_logs" ADD CONSTRAINT "FK_597e6df96098895bf19d4b5ea45" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "activity_logs" DROP CONSTRAINT "FK_597e6df96098895bf19d4b5ea45"`);
        await queryRunner.query(`ALTER TABLE "audit_logs" DROP CONSTRAINT "FK_9d53d8c4d4227c02e4476129d25"`);
        await queryRunner.query(`ALTER TABLE "cache_keys" DROP CONSTRAINT "FK_dea5419efccb62518e66a63b4d8"`);
        await queryRunner.query(`ALTER TABLE "cache_keys" DROP CONSTRAINT "FK_534d75a310fe04d609f01d05898"`);
        await queryRunner.query(`ALTER TABLE "refresh_tokens" DROP CONSTRAINT "FK_766ab81fa68d15204df19f83370"`);
        await queryRunner.query(`ALTER TABLE "refresh_tokens" DROP CONSTRAINT "FK_610102b60fea1455310ccd299de"`);
        await queryRunner.query(`ALTER TABLE "admins" DROP CONSTRAINT "FK_d27f7a7f01967e4a5e8ba73ebb0"`);
        await queryRunner.query(`ALTER TABLE "role_permissions" DROP CONSTRAINT "FK_06792d0c62ce6b0203c03643cdd"`);
        await queryRunner.query(`ALTER TABLE "role_permissions" DROP CONSTRAINT "FK_b4599f8b8f548d35850afa2d12c"`);
        await queryRunner.query(`ALTER TABLE "permissions" DROP CONSTRAINT "FK_e61928198c29bb2202922b08755"`);
        await queryRunner.query(`ALTER TABLE "modules" DROP CONSTRAINT "FK_a6637494664d871968306442f3b"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_b5fa115e88e67d287ba7a40223"`);
        await queryRunner.query(`DROP TABLE "activity_logs"`);
        await queryRunner.query(`DROP TYPE "public"."activity_logs_status_enum"`);
        await queryRunner.query(`DROP TYPE "public"."activity_logs_action_enum"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_2a495f3f3adbd1ceba0346ba16"`);
        await queryRunner.query(`DROP TABLE "audit_logs"`);
        await queryRunner.query(`DROP TYPE "public"."audit_logs_status_enum"`);
        await queryRunner.query(`DROP TYPE "public"."audit_logs_action_enum"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_b8ad02e0a2d004844b17af5e3f"`);
        await queryRunner.query(`DROP TABLE "settings"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_836026b660a661f0dbdc467bf1"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_4b2bf18167e94dce386d714c67"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_97672ac88f789774dd47f7c8be"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_2a32f641edba1d0f973c19cc94"`);
        await queryRunner.query(`DROP TABLE "users"`);
        await queryRunner.query(`DROP TYPE "public"."users_registrationstage_enum"`);
        await queryRunner.query(`DROP TABLE "cache_keys"`);
        await queryRunner.query(`DROP TYPE "public"."cache_keys_service_enum"`);
        await queryRunner.query(`DROP TYPE "public"."cache_keys_status_enum"`);
        await queryRunner.query(`DROP TABLE "refresh_tokens"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_aa69cff29dbc09a27c6b75addf"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_20f7eaea0ee98f1484256e59fd"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_6c06ce78e9eb2b8fed71a5c752"`);
        await queryRunner.query(`DROP TABLE "admins"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_e72912af85f8ca6ac65522f71e"`);
        await queryRunner.query(`DROP TABLE "roles"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_d430a02aad006d8a70f3acd7d0"`);
        await queryRunner.query(`DROP TABLE "role_permissions"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_d08be7a97addd61b394eba245c"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_7a0dec7dfde2c5c743fdadf9ba"`);
        await queryRunner.query(`DROP TABLE "permissions"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_4fc2237062f5e034c8f0537af4"`);
        await queryRunner.query(`DROP TABLE "modules"`);
    }

}
