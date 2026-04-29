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
>   created_at TIMESTAMP,
>   deleted_at TIMESTAMP
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

For each field (excluding `id`, `createdAt`, `updatedAt`, `deletedAt` — those are always added automatically), determine:

| Property          | What to extract                                                                                     |
| ----------------- | --------------------------------------------------------------------------------------------------- |
| **columnName**    | camelCase TypeScript name                                                                           |
| **dbColumn**      | snake_case DB column (derive from camelCase if not given)                                           |
| **tsType**        | TypeScript type (`string`, `number`, `boolean`, `Date`, enum union, entity type)                    |
| **typeormColumn** | TypeORM `@Column` options (`type`, `nullable`, `default`, `unique`, `length`, `precision`, `scale`) |
| **required**      | Whether the field is NOT NULL with no default                                                       |
| **isRelation**    | FK → another entity (`@ManyToOne`, `@OneToMany`, etc.)                                              |
| **isEnum**        | Whether it's an enum; if so, list the values and generate a `const enum` object                     |
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

- **Always extend `BaseEntity`** from `src/common/entities/base.entity` — it provides `id` (UUID), `generateUUID()`, `createdAt`, `updatedAt`, `deletedAt` (soft delete). Do NOT manually add these columns.
- Add `@BeforeInsert() @BeforeUpdate()` hooks only if the entity has password-like fields (auto-hash with bcrypt)
- For each field from the inventory: apply correct `@Column(...)` options, `@Index()`, `@Exclude()`, relation decorators
- Enum fields: define the `const` + `type` before the class; use `type: 'varchar'` in `@Column`
- FK fields: add both the raw FK column (`@Column('uuid') xyzId`) and the relation property (`@ManyToOne(() => Xyz, ...) xyz: Xyz`) with `@JoinColumn({ name: 'xyzId' })`
- Import only what is actually used

### 3.2 Create DTO — `dto/create-<module-name>.dto.ts`

Rules:

- Include only user-writable fields (skip auto-managed: `id`, `createdAt`, `updatedAt`, `deletedAt`)
- Required fields → no `@IsOptional()`
- Optional / nullable fields → `@IsOptional()`
- String fields → `@IsString()`, add `@MinLength`/`@MaxLength` where sensible
- Number fields → `@IsNumber()` or `@IsInt()`, add `@Min`/`@Max` where sensible
- Boolean fields → `@IsBoolean()` + `@Transform` coercion (string → boolean, matching PaginationFilterDto pattern)
- Enum fields → `@IsIn(Object.values(<EnumName>))` or `@IsEnum(<EnumName>)` as appropriate
- UUID FK fields → `@IsUUID()`
- Date string fields → `@IsDateString()` or `@IsString()`
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

- Always extends `PaginationFilterDto`
- Always include `search?: string` (applies ILIKE to searchable string fields identified in Step 2a)
- Always include `startDate?: string` and `endDate?: string` (filter on `createdAt`)
- For each **filterable** field from Step 2a:
  - Boolean → `@IsBoolean()` + `@Transform` coercion
  - Enum → `@IsIn(Object.values(<EnumName>))`
  - UUID FK → `@IsUUID() @IsOptional() <relation>Id?: string`
  - Number range → `min<Field>?: number` and `max<Field>?: number`
- Import `Transform` from `class-transformer` only when needed

### 3.5 Service — `services/<module-name>.service.ts`

Rules:

- Logger: `private readonly logger = new Logger(<ModuleName>Service.name)`
- Always inject: `@InjectRepository(<ModuleName>) private <moduleName>Repository: Repository<<ModuleName>>`
- IF `--with-image`: inject `S3ClientUtils` and `FileUploadService`
- IF `--with-transaction`: inject `DataSource`

**`create(dto, file?)`**

- IF `--with-transaction`: `return await this.dataSource.transaction(async (manager) => { ... })`; inside use `manager.create()` / `manager.save()`; if entity has relations to create together, handle them inside the transaction
- IF `--with-image`: upload via `this.fileUploadService.uploadProfileImage(file, '<moduleName>s/images')`, assign the key to the image field
- Use `repository.create({...dto})` then `repository.save()` (or manager equivalents)
- Check unique constraints declared in the entity — throw `ConflictException` for duplicates before insert
- Log creation

**`findAll(filter)`**

- Derive `skip` from `(page - 1) * limit`; apply only when `!getAll`
- `createQueryBuilder('<moduleName>').orderBy('<moduleName>.createdAt', 'DESC')`
- Left-join any relations that should be included in list results (based on Step 2b)
- `search` → `ILIKE` on all searchable string fields using `andWhere('(a ILIKE :term OR b ILIKE :term)', { term: '%...%' })`
- Each filterable field → its own `.andWhere()` clause guarded by `if (filter.field !== undefined)`
- `startDate` / `endDate` → `createdAt` range
- Return `{ data, total, page, limit }`

**`findOne(id)`**

- `findOne({ where: { id }, relations: [...] })` for any relations from Step 2b
- Throw `NotFoundException` if not found
- Return entity

**`update(id, dto, file?)`**

- IF `--with-transaction`: `return await this.dataSource.transaction(async (manager) => { ... })`; inside use `manager.create()` / `manager.save()`; if entity has relations to create together, handle them inside the transaction
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
- Return `{ message: '<ModuleName> with ID \'${id}\' has been successfully deleted' }`

### 3.6 Controller — `controllers/<module-name>.controller.ts`

Rules:

- `@Controller({ path: '<module-name>s', version: '1' })`
- `@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))`
- UNLESS `--no-auth`: `@UseGuards(JwtAuthGuard, PermissionsGuard)`
- IF `--public <routes>`: import `Public` from `src/v1/auth/decorators/public.decorator` and add `@Public()` to each listed route method; `@Public()` bypasses `JwtAuthGuard` for that endpoint only — do NOT add `@RequirePermissions` or `@LogActivity` on public routes

**POST `/`**

- UNLESS `--no-auth`: `@RequirePermissions([{ module: PermissionModule.<MODULE_NAME>, permission: 'create' }, { module: PermissionModule.<MODULE_NAME>_LIST, permission: 'create' }])`
- UNLESS `--no-auth`: `@LogActivity({ action: ActivityAction.CREATE, description: '<ModuleName> created successfully', resourceType: '<moduleName>', getResourceId: (result: <ModuleName>) => result.id?.toString() })`
- IF `--with-image`: `@UseInterceptors(FileInterceptor('<imageFieldName>', profileImageInterceptorOptions))` — import `profileImageInterceptorOptions` from `src/common/utils/file-interceptor.util`; use the actual image field name from the entity
- Return `ResponseUtil.created(result, '<ModuleName> created successfully')`

**GET `/`**

- UNLESS `--no-auth`: `@RequirePermissions([{ module: PermissionModule.<MODULE_NAME>, permission: 'read' }, { module: PermissionModule.<MODULE_NAME>_LIST, permission: 'read' }])`
- IF `--with-image`: `@ResolvePresignedUrls('<imageFieldName>')` — import from `src/common/decorators/presigned-urls.decorator`; use the actual image field name from the entity
- `@Query() filters: Filter<ModuleName>Dto`
- `filters.getAll` → `ResponseUtil.success(result.data, 'All <moduleName>s retrieved successfully')`
- else → `ResponseUtil.paginated(result.data, result.total, result.page, result.limit, '<ModuleName>s retrieved successfully')`

**GET `/:id`**

- UNLESS `--no-auth`: `@RequirePermissions([{ module: PermissionModule.<MODULE_NAME>, permission: 'read' }, { module: PermissionModule.<MODULE_NAME>_LIST, permission: 'read' }])`
- IF `--with-image`: `@ResolvePresignedUrls('<imageFieldName>')` — import from `src/common/decorators/presigned-urls.decorator`; use the actual image field name from the entity
- Return `ResponseUtil.success(result, '<ModuleName> retrieved by ID ${id} successfully')`

**PATCH `/:id`**

- UNLESS `--no-auth`: `@RequirePermissions([{ module: PermissionModule.<MODULE_NAME>, permission: 'update' }, { module: PermissionModule.<MODULE_NAME>_LIST, permission: 'update' }])`
- UNLESS `--no-auth`: `@LogActivity({ action: ActivityAction.UPDATE, description: '<ModuleName> updated successfully', resourceType: '<moduleName>', getResourceId: (result: <ModuleName>) => result.id?.toString() })`
- IF `--with-image`: `@UseInterceptors(FileInterceptor('<imageFieldName>', profileImageInterceptorOptions))` — same config as POST
- Return `ResponseUtil.updated(result, '<ModuleName> updated successfully')`

**DELETE `/:id`**

- UNLESS `--no-auth`: `@RequirePermissions([{ module: PermissionModule.<MODULE_NAME>, permission: 'delete' }, { module: PermissionModule.<MODULE_NAME>_LIST, permission: 'delete' }])`
- UNLESS `--no-auth`: `@LogActivity({ action: ActivityAction.DELETE, description: '<ModuleName> deleted successfully', resourceType: '<moduleName>', getResourceId: (params: { id: string }) => params.id })`
- Return `ResponseUtil.success(result, '<ModuleName> deleted successfully')`

### 3.7 Module — `<module-name>.module.ts`

```typescript
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
// import related entities too if they are used in this module's repository
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

---

## Step 4 — Update existing files

### 4.1 `src/v1/auth/entities/permission.entity.ts`

Append to the `PermissionModule` enum:

```typescript
  <MODULE_NAME> = '<MODULE_NAME>',
  <MODULE_NAME>_LIST = '<MODULE_NAME>_LIST',
```

### 4.2 `src/v1/auth/seeders/auth.seeder.ts`

In the `modulesToSeed` array inside `seed()`, add:

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

Import `<ModuleName>Module` from `./v1/<module-name>/<module-name>.module` and add it to the `imports` array.

---

## Step 5 — Post-generation report

After writing all files, output a summary table:

| #          | Action                                                         | Path |
| ---------- | -------------------------------------------------------------- | ---- |
| ✅ created | `src/v1/<module-name>/entities/<module-name>.entity.ts`        |      |
| ✅ created | `src/v1/<module-name>/dto/create-<module-name>.dto.ts`         |      |
| ✅ created | `src/v1/<module-name>/dto/update-<module-name>.dto.ts`         |      |
| ✅ created | `src/v1/<module-name>/dto/filter-<module-name>.dto.ts`         |      |
| ✅ created | `src/v1/<module-name>/services/<module-name>.service.ts`       |      |
| ✅ created | `src/v1/<module-name>/controllers/<module-name>.controller.ts` |      |
| ✅ created | `src/v1/<module-name>/<module-name>.module.ts`                 |      |
| ✅ updated | `src/v1/auth/entities/permission.entity.ts`                    |      |
| ✅ updated | `src/v1/auth/seeders/auth.seeder.ts`                           |      |
| ✅ updated | `src/app.module.ts`                                            |      |

Then remind the user:

1. **Run migration:** `npx typeorm migration:generate src/migrations/<ModuleName>Migration -d src/data-source.ts`
2. If `--no-auth`: add your own guards or mark routes with `@Public()` individually.
   - `@Public()` is imported from `src/v1/auth/decorators/public.decorator` and bypasses `JwtAuthGuard` for a single route without removing the guard from the whole controller.
3. If `--with-image`: ensure AWS S3 env vars are set in `.env`.
4. If new relations reference entities from other modules, verify those modules export the relevant services/repositories if needed.
