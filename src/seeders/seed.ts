import { NestFactory } from '@nestjs/core';
import { SeederModule } from './seeder.module';
import { AuthSeeder } from '../v1/auth/seeders/auth.seeder';
import { SettingSeeder } from '../v1/setting/seeders/setting.seeder';

async function runSeeders() {
  console.log('🌱 Starting database seeding...');

  const app = await NestFactory.createApplicationContext(SeederModule);

  try {
    // Get seeder instances
    const authSeeder = app.get(AuthSeeder);
    const settingSeeder = app.get(SettingSeeder);

    // Run seeders in order
    console.log(
      '📝 Seeding authentication data (roles, permissions, users)...',
    );
    await authSeeder.seed();
    console.log('✅ Authentication seeding completed');

    console.log('⚙️ Seeding application settings...');
    await settingSeeder.seed();
    console.log('✅ Settings seeding completed');

    console.log('🎉 All seeders completed successfully!');
  } catch (error) {
    console.error('❌ Seeding failed:', error);
    process.exit(1);
  } finally {
    await app.close();
  }
}

// Run the seeder
runSeeders().catch((error) => {
  console.error('❌ Fatal error during seeding:', error);
  process.exit(1);
});
