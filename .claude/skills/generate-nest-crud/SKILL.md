---
name: generate-nest-crud
description: Generate a complete, fully-functional NestJS CRUD module following the exact patterns of this project, driven by a user-provided entity structure.
---

# Generate Nest CRUD

Generate a complete, fully-functional NestJS CRUD module following the exact patterns of this project, driven by a user-provided entity structure.

## Usage

```
/generate-crud <ModuleName> [--with-image] [--with-transaction] [--no-auth]
```

Then the user provides the entity structure (see "Entity input" below).

**Examples:**

- `/generate-crud Product` — basic CRUD
- `/generate-crud Product --with-image` — includes S3 image upload
- `/generate-crud Order --with-transaction` — wraps create/update in a DataSource transaction
- `/generate-crud Category --no-auth` — skips JWT/permission guards

---

## Step 1 — Parse args and ask for entity structure

Parse flags from the invocation args:

- `ModuleName` → PascalCase entity name (e.g. `Product`)
- Derive: `moduleName` (camelCase), `module-name` (kebab-case), `module_name` (snake_case), `MODULE_NAME` (SCREAMING_SNAKE)
- `--with-image` → include S3 image upload logic
- `--with-transaction` → wrap `create()`, `update()` in `DataSource.transaction()`
- `--no-auth` → omit `JwtAuthGuard`, `PermissionsGuard`, `@RequirePermissions`, `@LogActivity` from the entire controller
- `--public <routes>` → mark specific routes as publicly accessible with `@Public()` while keeping auth on the rest (comma-separated: `create,findAll,findOne,update,remove`)

If `ModuleName` is missing, ask: "What is the module name? (e.g. /generate-crud Product)"

**After parsing args, immediately ask the user for the entity structure before generating anything:**

> Please provide the database entity structure for `<ModuleName>`. You can describe it in any of these formats:
>
> **Option A — SQL table:**
>
> ```sql
> CREATE TABLE products (
>   id UUID PRIMARY KEY,
>   name VARCHAR(200) NOT NULL,
>   price DECIMAL(10,2) NOT NULL,
>   category_id UUID REFERENCES categories(id),
>   status VARCHAR(20) DEFAULT 'active',
>   created_at TIMESTAMPTZ,
>   deleted_at TIMESTAMPTZ
> );
> ```
>
> **Option B — Plain field list:**
>
> ```
> name: string, required
> price: number, required
> categoryId: UUID (FK → categories), required
> status: enum('active','inactive'), default 'active'
> description: string, optional
> ```
>
> **Option C — Existing TypeORM entity (paste the class):**
>
> ```typescript
> @Entity()
> export class Product { ... }
> ```
>
> Include: column names, types, nullable/required, defaults, enums, FK relations, unique constraints, and any fields that should be searchable/filterable.

Wait for the user's response before proceeding to Step 2.

---

## Step 2 — Analyse the provided entity structure

Read the user's input carefully and extract:

### 2a. Field inventory

For each field (excluding `id`, `createdAt`, `updatedAt`, `deletedAt` — those are always added automatically via `BaseEntity`), determine:

| Property          | What to extract                                                                                     |
| ----------------- | --------------------------------------------------------------------------------------------------- |
| **columnName**    | camelCase TypeScript name                                                                           |
| **dbColumn**      | snake_case DB column (derive from camelCase if not given)                                           |
| **tsType**        | TypeScript type (`string`, `number`, `boolean`, `Date`, enum union, entity type)                    |
| **typeormColumn** | TypeORM `@Column` options (`type`, `nullable`, `default`, `unique`, `length`, `precision`, `scale`) |
| **required**      | Whether the field is NOT NULL with no default                                                       |
| **isRelation**    | FK → another entity (`@ManyToOne`, `@OneToMany`, etc.)                                              |
| **isEnum**        | Whether it's an enum; if so, list the values and generate a `const` object + type alias             |
| **isIndex**       | Whether to add `@Index()`                                                                           |
| **isUnique**      | Whether to add `@Column({ unique: true })`                                                          |
| **isExcluded**    | Whether to `@Exclude()` (e.g. password-like fields)                                                 |
| **isSearchable**  | String fields to include in `ILIKE` search in `findAll`                                             |
| **isFilterable**  | Fields to expose as explicit query filters (enums, booleans, FK ids, date ranges)                   |
| **isImageField**  | The image URL storage field (only if `--with-image`)                                                |

### 2b. Relation inventory

For each FK / relation field:

- Which entity it points to (import path if in the same `v1/` tree, or note if external)
- Relation type: `@ManyToOne`, `@OneToMany`, `@OneToOne`, `@ManyToMany`
- `@JoinColumn` name (the FK column)
- Whether `onDelete: 'CASCADE' | 'SET NULL'`
- Whether to include the relation in `findOne` / `findAll` via `.leftJoinAndSelect()`

### 2c. Image field detection

If `--with-image` is set, identify which field stores the image key (e.g. `imageUrl`, `thumbnailUrl`, `coverImageUrl`). Use that exact field name throughout — do **not** hardcode `imageUrl` if the user named it differently.

### 2d. Enum detection

For every enum field: generate a `const` object AND a type alias (same pattern as `LoginProvider` in `user.entity.ts`):

```typescript
export const <EnumName> = {
  VALUE_A: 'value_a',
  VALUE_B: 'value_b',
} as const;
export type <EnumName> = (typeof <EnumName>)[keyof typeof <EnumName>];
```

Use `type: 'varchar'` (not `type: 'enum'`) in the `@Column` decorator — matching the project pattern.

---

## Step 3 — Generate all files

Use the extracted field inventory to produce real, accurate code. **Do not fall back to generic `name`/`description` placeholders** — every field the user specified must appear.

All paths are relative to `src/v1/<module-name>/`.

### 3.1 Entity — `entities/<module-name>.entity.ts`

Rules:

- **Always extend `BaseEntity`** from `src/common/entities/base.entity` — it provides `id` (UUID with `@PrimaryColumn('uuid')` + `@BeforeInsert() generateUUID()`), `createdAt`, `updatedAt` (`@CreateDateColumn({ type: 'timestamptz' })`), and `deletedAt` (`@DeleteDateColumn({ type: 'timestamptz' })`). Do NOT manually add these columns.
- Add `@BeforeInsert() @BeforeUpdate()` hooks only if the entity has password-like fields (auto-hash with bcrypt)
- For each field from the inventory: apply correct `@Column(...)` options, `@Index()`, `@Exclude()`, relation decorators
- **Date/timestamp columns**: always use `type: 'timestamptz'` — never plain `'timestamp'`:
  ```typescript
  @Column({ type: 'timestamptz', nullable: true })
  publishedAt: Date | null;
  ```
- Enum fields: define the `const` + `type` before the class; use `type: 'varchar'` in `@Column`
- FK fields: add both the raw FK column (`@Column('uuid') xyzId: string`) and the relation property (`@ManyToOne(() => Xyz, ...) xyz: Xyz`) with `@JoinColumn({ name: 'xyzId' })`
- Import only what is actually used

### 3.2 Create DTO — `dto/create-<module-name>.dto.ts`

Rules:

- Include only user-writable fields (skip auto-managed: `id`, `createdAt`, `updatedAt`, `deletedAt`)
- Required fields → no `@IsOptional()`
- Optional / nullable fields → `@IsOptional()`
- String fields → `@IsString()`, add `@MinLength`/`@MaxLength` where sensible
- Number fields → `@IsNumber()` or `@IsInt()`, add `@Min`/`@Max` where sensible
- Boolean fields → `@IsBoolean()` + exact `@Transform` coercion pattern:
  ```typescript
  @IsOptional()
  @IsBoolean()
  @Transform(({ value }) => {
    if (value === undefined || value === null) return undefined;
    if (value === 'true' || value === '1' || value === true) return true;
    if (value === 'false' || value === '0' || value === false) return false;
    return undefined;
  })
  isActive?: boolean;
  ```
- Enum fields → `@IsIn(Object.values(<EnumName>))`
- UUID FK fields → `@IsUUID()`
- Date string fields → `@IsDateString()`
- Email fields → `@IsEmail()`
- IF `--with-image`: include the image URL field as `@IsOptional() @IsString()`
- Import `Transform` from `class-transformer` only when boolean coercion is needed

### 3.3 Update DTO — `dto/update-<module-name>.dto.ts`

```typescript
import { PartialType } from '@nestjs/mapped-types';
import { Create<ModuleName>Dto } from './create-<module-name>.dto';

export class Update<ModuleName>Dto extends PartialType(Create<ModuleName>Dto) {}
```

### 3.4 Filter DTO — `dto/filter-<module-name>.dto.ts`

Rules:

- Always extends `PaginationFilterDto` from `src/common/dto/pagination-filter.dto`
- `PaginationFilterDto` already provides `page`, `limit`, `getAll` — do NOT redeclare them
- Always include `search?: string` with `@IsOptional() @IsString()` (applies ILIKE to searchable string fields)
- Always include `startDate?: string` and `endDate?: string` as `@IsOptional() @IsString()` — NOT `@IsDateString()`:
  ```typescript
  @IsOptional()
  @IsString()
  startDate?: string;

  @IsOptional()
  @IsString()
  endDate?: string;
  ```
- For each **filterable** field from Step 2a:
  - Boolean → `@IsOptional() @IsBoolean()` + exact `@Transform` coercion (same pattern as Create DTO)
  - Enum → `@IsOptional() @IsIn(Object.values(<EnumName>))`
  - UUID FK → `@IsOptional() @IsUUID() <relation>Id?: string`
  - Number range → `@IsOptional() @IsNumber() min<Field>?: number` and `max<Field>?: number`
- Import `Transform` from `class-transformer` only when boolean coercion is needed

### 3.5 Service — `services/<module-name>.service.ts`

Rules:

- Logger: `private readonly logger = new Logger(<ModuleName>Service.name)`
- Always inject: `@InjectRepository(<ModuleName>) private <moduleName>Repository: Repository<<ModuleName>>`
- IF `--with-image`: inject `S3ClientUtils` and `FileUploadService`
- IF `--with-transaction`: inject `DataSource`
- **Always import date utilities** from `src/common/utils/date-time.util` for any date logic — never use raw `new Date()`, `Date.now()`, or `.setDate()` directly:
  ```typescript
  import { nowUtc, parseRangeStart, parseRangeEnd } from 'src/common/utils/date-time.util';
  ```

**`create(dto, file?)`**

- IF `--with-transaction`: `return await this.dataSource.transaction(async (manager) => { ... })`; inside use `manager.create()` / `manager.save()`
- IF `--with-image`: upload via `this.fileUploadService.uploadProfileImage(file, '<moduleName>s/images')`, assign the key to the image field
- Use `repository.create({...dto})` then `repository.save()` (or manager equivalents)
- Check unique constraints declared in the entity — throw `ConflictException` for duplicates before insert
- For any "current timestamp" field (e.g. `publishedAt: nowUtc()`): use `nowUtc()` not `new Date()`
- Log creation

**`findAll(filter)`**

- Derive `skip` from `(page - 1) * limit`; apply only when `!getAll`
- `createQueryBuilder('<moduleName>').orderBy('<moduleName>.createdAt', 'DESC')`
- Left-join any relations that should be included in list results (based on Step 2b)
- `search` → `ILIKE` on all searchable string fields using `andWhere('(<moduleName>.a ILIKE :term OR <moduleName>.b ILIKE :term)', { term: '%...%' })`
- Each filterable field → its own `.andWhere()` clause guarded by `if (filter.field !== undefined)`
- **Date range** — always use `parseRangeStart` / `parseRangeEnd` (treats bare dates as Myanmar local midnight/end-of-day, converting to UTC):
  ```typescript
  import { nowUtc, parseRangeStart, parseRangeEnd } from 'src/common/utils/date-time.util';

  if (filter.startDate) {
    qb.andWhere('<moduleName>.createdAt >= :startDate', {
      startDate: parseRangeStart(filter.startDate),
    });
  }
  if (filter.endDate) {
    qb.andWhere('<moduleName>.createdAt <= :endDate', {
      endDate: parseRangeEnd(filter.endDate),
    });
  }
  ```
- Return `{ data, total, page, limit }`

**`findOne(id)`**

- `findOne({ where: { id }, relations: [...] })` for any relations from Step 2b
- Throw `NotFoundException` if not found
- Return entity

**`update(id, dto, file?)`**

- IF `--with-transaction`: wrap in `this.dataSource.transaction(async (manager) => { ... })`
- Fetch existing entity → `NotFoundException` if missing
- Check unique constraints on changed fields → `ConflictException`
- IF `--with-image`: handle new file upload, swap key, delete old key from S3 when changed
- `repository.preload({ id, ...dto })` then `repository.save()`
- Log update
- Return saved entity

**`remove(id)`**

- Fetch existing entity → `NotFoundException`
- IF `--with-image`: delete image from S3
- `repository.softRemove(entity)`
- Log deletion
- Return `{ message: "<ModuleName> with ID '${id}' has been successfully deleted" }`

### 3.6 Controller — `controllers/<module-name>.controller.ts`

Rules:

- `@Controller({ path: '<module-name>s', version: '1' })`
- `@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))`
- UNLESS `--no-auth`: `@UseGuards(JwtAuthGuard, PermissionsGuard)`
- IF `--public <routes>`: import `Public` from `src/v1/auth/decorators/public.decorator` and add `@Public()` to each listed route method; `@Public()` bypasses `JwtAuthGuard` for that endpoint only — do NOT add `@RequirePermissions` or `@LogActivity` on public routes

**Import paths:**
```typescript
import { JwtAuthGuard } from 'src/v1/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/v1/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/v1/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/v1/auth/entities/permission.entity';
import { LogActivity } from 'src/v1/activity-log/decorators/log-activity.decorator';
import { LogAction } from 'src/v1/activity-log/constants/log-action.enum';
import { ResponseUtil } from 'src/common/utils/response.util';
// IF --with-image:
import { ResolvePresignedUrls } from 'src/common/decorators/presigned-urls.decorator';
import { FileInterceptor } from '@nestjs/platform-express';
import { profileImageInterceptorOptions } from 'src/common/utils/file-interceptor.util';
// IF --public:
import { Public } from 'src/v1/auth/decorators/public.decorator';
```

**POST `/`**

- UNLESS `--no-auth`:
  ```typescript
  @RequirePermissions(
    { module: PermissionModule.<MODULE_NAME>, permission: 'create' },
    { module: PermissionModule.<MODULE_NAME>_LIST, permission: 'create' },
  )
  @LogActivity({
    action: LogAction.CREATE,
    description: '<ModuleName> created successfully',
    resourceType: '<moduleName>',
    getResourceId: (result: <ModuleName>) => result.id?.toString(),
  })
  ```
- IF `--with-image`: `@UseInterceptors(FileInterceptor('<imageFieldName>', profileImageInterceptorOptions))`; add `@UploadedFile() file: Express.Multer.File` parameter
- Return `ResponseUtil.created(result, '<ModuleName> created successfully')`

**GET `/`**

- UNLESS `--no-auth`:
  ```typescript
  @RequirePermissions(
    { module: PermissionModule.<MODULE_NAME>, permission: 'read' },
    { module: PermissionModule.<MODULE_NAME>_LIST, permission: 'read' },
  )
  ```
- IF `--with-image`: `@ResolvePresignedUrls('<imageFieldName>')`
- `@Query() filters: Filter<ModuleName>Dto`
- `filters.getAll` → `ResponseUtil.success(result.data, 'All <moduleName>s retrieved successfully')`
- else → `ResponseUtil.paginated(result.data, result.total, result.page, result.limit, '<ModuleName>s retrieved successfully')`

**GET `/:id`**

- UNLESS `--no-auth`:
  ```typescript
  @RequirePermissions(
    { module: PermissionModule.<MODULE_NAME>, permission: 'read' },
    { module: PermissionModule.<MODULE_NAME>_LIST, permission: 'read' },
  )
  ```
- IF `--with-image`: `@ResolvePresignedUrls('<imageFieldName>')`
- Return `ResponseUtil.success(result, '<ModuleName> retrieved by ID ${id} successfully')`

**PATCH `/:id`**

- UNLESS `--no-auth`:
  ```typescript
  @RequirePermissions(
    { module: PermissionModule.<MODULE_NAME>, permission: 'update' },
    { module: PermissionModule.<MODULE_NAME>_LIST, permission: 'update' },
  )
  @LogActivity({
    action: LogAction.UPDATE,
    description: '<ModuleName> updated successfully',
    resourceType: '<moduleName>',
    getResourceId: (result: <ModuleName>) => result.id?.toString(),
  })
  ```
- IF `--with-image`: `@UseInterceptors(FileInterceptor('<imageFieldName>', profileImageInterceptorOptions))`
- Return `ResponseUtil.updated(result, '<ModuleName> updated successfully')`

**DELETE `/:id`**

- UNLESS `--no-auth`:
  ```typescript
  @RequirePermissions(
    { module: PermissionModule.<MODULE_NAME>, permission: 'delete' },
    { module: PermissionModule.<MODULE_NAME>_LIST, permission: 'delete' },
  )
  @LogActivity({
    action: LogAction.DELETE,
    description: '<ModuleName> deleted successfully',
    resourceType: '<moduleName>',
    getResourceId: (params: { id: string }) => params.id,
  })
  ```
- Return `ResponseUtil.success(result, '<ModuleName> deleted successfully')`

### 3.7 Module — `<module-name>.module.ts`

```typescript
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { <ModuleName> } from './entities/<module-name>.entity';
import { <ModuleName>Service } from './services/<module-name>.service';
import { <ModuleName>Controller } from './controllers/<module-name>.controller';

@Module({
  imports: [TypeOrmModule.forFeature([<ModuleName>])],
  providers: [<ModuleName>Service],
  controllers: [<ModuleName>Controller],
  exports: [<ModuleName>Service],
})
export class <ModuleName>Module {}
```

If the module uses `S3ClientUtils`, `FileUploadService`, or other shared services: those are provided by `CommonModule` (already imported globally) — do NOT redeclare them in `providers`.

---

## Step 4 — Update existing files

### 4.1 `src/v1/auth/entities/permission.entity.ts`

Append to the `PermissionModule` enum:

```typescript
  <MODULE_NAME> = '<MODULE_NAME>',
  <MODULE_NAME>_LIST = '<MODULE_NAME>_LIST',
```

### 4.2 `src/v1/auth/seeders/auth.seeder.ts`

In the `modulesToSeed` array, add:

```typescript
{
  name: '<ModuleName>',
  code: PermissionModule.<MODULE_NAME>,
  children: [
    {
      name: '<ModuleName> List',
      code: PermissionModule.<MODULE_NAME>_LIST,
    },
  ],
},
```

### 4.3 `src/app.module.ts`

Import `<ModuleName>Module` from `./v1/<module-name>/<module-name>.module` and add it to the `imports` array alongside the existing domain modules (`AuthModule`, `UserModule`, `AdminModule`, etc.).

---

## Step 5 — Post-generation report

After writing all files, output a summary table:

| #          | Action    | Path                                                           |
| ---------- | --------- | -------------------------------------------------------------- |
| ✅ created | entity    | `src/v1/<module-name>/entities/<module-name>.entity.ts`        |
| ✅ created | create DTO | `src/v1/<module-name>/dto/create-<module-name>.dto.ts`        |
| ✅ created | update DTO | `src/v1/<module-name>/dto/update-<module-name>.dto.ts`        |
| ✅ created | filter DTO | `src/v1/<module-name>/dto/filter-<module-name>.dto.ts`        |
| ✅ created | service   | `src/v1/<module-name>/services/<module-name>.service.ts`       |
| ✅ created | controller | `src/v1/<module-name>/controllers/<module-name>.controller.ts` |
| ✅ created | module    | `src/v1/<module-name>/<module-name>.module.ts`                 |
| ✅ updated | permissions | `src/v1/auth/entities/permission.entity.ts`                  |
| ✅ updated | seeder    | `src/v1/auth/seeders/auth.seeder.ts`                           |
| ✅ updated | app module | `src/app.module.ts`                                           |

Then remind the user:

1. **Run migration:** `npm run migration:generate -- src/migrations/<ModuleName>Migration`
2. If `--no-auth`: add your own guards or mark routes with `@Public()` individually.
   - `@Public()` is imported from `src/v1/auth/decorators/public.decorator` and bypasses `JwtAuthGuard` for a single route without removing the guard from the whole controller.
3. If `--with-image`: ensure AWS S3 env vars (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_S3_BUCKET`, `AWS_REGION`) are set in `.env`.
4. If new relations reference entities from other modules, add those modules to the `imports` array of `<ModuleName>Module` and ensure the related module exports its service/repository.

---

## Key project patterns reference

### Date handling (always use `date-time.util.ts`)

```typescript
import {
  nowUtc,           // replaces new Date()
  nowIso,           // replaces new Date().toISOString()
  addMinutes,       // OTP expiry: addMinutes(OTP_TTL_MINUTES)
  addHours,         // e.g. addHours(1)
  addDays,          // token expiry: addDays(REFRESH_TOKEN_TTL_DAYS)
  subtractDays,     // log cleanup: subtractDays(LOG_RETENTION_DAYS)
  isExpired,        // replaces new Date() > expiresAt (accepts Date | null)
  parseRangeStart,  // filter start: treats bare "YYYY-MM-DD" as Myanmar midnight
  parseRangeEnd,    // filter end: treats bare "YYYY-MM-DD" as Myanmar 23:59:59
  toMyanmarDisplay, // display formatting for Myanmar timezone
  OTP_TTL_MINUTES,        // 10
  REFRESH_TOKEN_TTL_DAYS, // 30
  LOG_RETENTION_DAYS,     // 90
} from 'src/common/utils/date-time.util';
```

### `@RequirePermissions` — spread args, not array

```typescript
// ✅ correct
@RequirePermissions(
  { module: PermissionModule.PRODUCT, permission: 'create' },
  { module: PermissionModule.PRODUCT_LIST, permission: 'create' },
)

// ❌ wrong — do not wrap in an array
@RequirePermissions([...])
```

### `@LogActivity` — use `LogAction`, not `ActivityAction`

```typescript
import { LogActivity } from 'src/v1/activity-log/decorators/log-activity.decorator';
import { LogAction } from 'src/v1/activity-log/constants/log-action.enum';

@LogActivity({
  action: LogAction.CREATE,   // ← LogAction enum, not ActivityAction
  description: 'Product created successfully',
  resourceType: 'product',
  getResourceId: (result: Product) => result.id?.toString(),
})
```

### `BaseEntity` provides (do not re-declare)

```typescript
id: string;          // @PrimaryColumn('uuid') + @BeforeInsert() generateUUID()
createdAt: Date;     // @CreateDateColumn({ type: 'timestamptz' })
updatedAt: Date;     // @UpdateDateColumn({ type: 'timestamptz' })
deletedAt?: Date;    // @DeleteDateColumn({ type: 'timestamptz' }) + @Index()
```

### Explicit timestamp columns — always `timestamptz`

```typescript
// ✅ correct
@Column({ type: 'timestamptz', nullable: true })
publishedAt: Date | null;

// ❌ wrong
@Column({ type: 'timestamp', nullable: true })
publishedAt: Date | null;
```

### Filter DTO `startDate`/`endDate` — `@IsString()` not `@IsDateString()`

```typescript
@IsOptional()
@IsString()
startDate?: string;

@IsOptional()
@IsString()
endDate?: string;
```
