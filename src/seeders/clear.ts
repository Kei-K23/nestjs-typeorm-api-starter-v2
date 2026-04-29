import { NestFactory } from '@nestjs/core';
import { SeederModule } from './seeder.module';
import { DataSource } from 'typeorm';

async function clearDatabase() {
  console.log('🧹 Starting database cleanup...');

  const app = await NestFactory.createApplicationContext(SeederModule);
  const dataSource = app.get(DataSource);

  try {
    const truncateMode = true;

    if (truncateMode) {
      console.log('🗑️ Truncating all tables...');

      // Get all base table names (exclude views)
      const tables = await dataSource.query(`
        SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_type = 'BASE TABLE'
          AND table_name <> 'migrations'
      `);

      // Truncate all tables and reset identity, cascade to dependents
      for (const row of tables) {
        const tableName = row.table_name;
        await dataSource.query(
          `TRUNCATE TABLE "${tableName}" RESTART IDENTITY CASCADE;`,
        );
        console.log(`✅ Truncated table: ${tableName}`);
      }

      console.log('🎉 All tables truncated successfully!');
    } else {
      console.log('🗑️ Dropping and recreating database schema...');

      // Drop all tables and recreate schema
      await dataSource.dropDatabase();
      await dataSource.synchronize();

      console.log('🎉 Database schema recreated successfully!');
    }
  } catch (error) {
    console.error('❌ Database cleanup failed:', error);
    process.exit(1);
  } finally {
    await app.close();
  }
}

// Run the cleanup
clearDatabase().catch((error) => {
  console.error('❌ Fatal error during cleanup:', error);
  process.exit(1);
});
