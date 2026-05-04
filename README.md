# NestJS + TypeORM Backend API Template

A production-ready NestJS backend template with TypeORM, PostgreSQL, Redis, JWT authentication, BullMQ queues, AWS S3 file storage, and structured logging.

---

## Tech Stack

| Layer          | Technology                                 |
| -------------- | ------------------------------------------ |
| Framework      | NestJS 11                                  |
| Language       | TypeScript 5                               |
| ORM            | TypeORM 0.3                                |
| Database       | PostgreSQL                                 |
| Cache / Queue  | Redis (BullMQ + cache-manager-redis-store) |
| Auth           | JWT (Passport) + Refresh Tokens + 2FA      |
| File Storage   | AWS S3 (presigned URLs)                    |
| Notifications  | BullMQ queues → Email (Nodemailer) + SMS   |
| Logging        | Winston + Daily Rotate File                |
| Compiler       | SWC (fast builds)                          |
| API Versioning | URI-based (`/api/v1/...`)                  |

---

## Full Directory Tree

```
nestjs-typeorm-backend-template/
│
├── .env.example                        # All required env vars documented
├── .gitignore
├── .prettierrc
├── .swcrc                              # SWC compiler config (replaces ts-node for speed)
├── eslint.config.mjs
├── nest-cli.json
├── tsconfig.json
├── tsconfig.build.json
├── config.nginx                        # NGINX reverse-proxy config
├── package.json
│
├── .github/
│   └── workflows/
│       ├── deploy.yml                  # Production CI/CD pipeline
│       └── deploy-uat.yml              # UAT / staging pipeline
│
├── test/                               # End-to-end tests (Jest + Supertest)
│   ├── app.e2e-spec.ts
│   └── jest-e2e.json
│
└── src/
    ├── main.ts                         # App bootstrap entry point
    ├── app.module.ts                   # Root module — wires all feature modules
    ├── app.controller.ts               # Health-check / root route
    ├── app.service.ts
    ├── data-source.ts                  # Standalone TypeORM DataSource (used by CLI)
    │
    ├── types/
    │   └── express.d.ts                # Extends Express Request (adds user, etc.)
    │
    ├── migrations/                     # TypeORM migration files
    │   └── <timestamp>-init.ts
    │
    ├── seeders/                        # Root seed orchestrators
    │   ├── seed.ts                     # npm run db:seed
    │   └── clear.ts                    # npm run db:clear
    │
    ├── common/                         # @Global() shared infrastructure
    │   ├── common.module.ts
    │   ├── config/
    │   │   └── logger.config.ts        # Winston transport config
    │   ├── dto/
    │   │   └── pagination-filter.dto.ts  # Base DTO: page, limit, sort
    │   ├── filters/
    │   │   └── http-exception.filter.ts  # Global error → standard JSON shape
    │   ├── interceptors/
    │   │   └── response.interceptor.ts   # Wraps all responses in ApiResponse
    │   ├── interfaces/
    │   │   └── api-response.interface.ts # { success, data, message, meta }
    │   ├── utils/
    │   │   ├── response.util.ts          # ResponseUtil.success() / .error()
    │   │   ├── email-service.utils.ts    # Nodemailer wrapper (reads SMTP from DB)
    │   │   ├── sms-pho-service.utils.ts  # Phandeeyar SMS gateway wrapper
    │   │   ├── s3-client.utils.ts        # S3 upload + presigned URL helpers
    │   │   └── user-agent.util.ts        # Parses UA string → device info
    │   └── validators/
    │       └── nrc-format.validator.ts   # Custom class-validator for Myanmar NRC
    │
    ├── notification/                   # Async notification queue system
    │   ├── notification.module.ts
    │   ├── notification.service.ts     # Enqueues email / SMS jobs
    │   ├── constants/
    │   │   └── notification.constants.ts  # Queue name constants
    │   ├── interfaces/
    │   │   └── notification-jobs.interface.ts  # Job payload types
    │   └── processors/
    │       ├── email.processor.ts      # BullMQ worker: consumes email queue
    │       └── sms.processor.ts        # BullMQ worker: consumes SMS queue
    │
    └── v1/                             # Versioned feature modules (URI: /api/v1/)
        │
        ├── auth/                       # Authentication & Authorization
        │   ├── auth.module.ts
        │   ├── controllers/
        │   │   ├── auth.controller.ts  # POST login/register/2FA/password flows
        │   │   └── role.controller.ts  # CRUD for roles (admin only)
        │   ├── decorators/
        │   │   ├── current-user.decorator.ts    # @CurrentUser() param decorator
        │   │   ├── roles.decorator.ts           # @Roles('superadmin') metadata
        │   │   └── permissions.decorator.ts     # @Permissions('user:read') metadata
        │   ├── dto/
        │   │   ├── admin-login.dto.ts
        │   │   ├── user-login.dto.ts
        │   │   ├── user-google-login.dto.ts     # OAuth Google token exchange
        │   │   ├── user-apple-login.dto.ts      # OAuth Apple token exchange
        │   │   ├── user-register-otp-request.dto.ts
        │   │   ├── user-register-otp-verify.dto.ts
        │   │   ├── user-register-password-setup.dto.ts
        │   │   ├── user-register-account-setup.dto.ts
        │   │   ├── refresh-token.dto.ts
        │   │   ├── update-profile.dto.ts
        │   │   ├── change-password.dto.ts
        │   │   ├── forgot-password-send-otp.dto.ts
        │   │   ├── user-forgot-password-send-otp.dto.ts
        │   │   ├── verify-password-reset-otp-code.dto.ts
        │   │   ├── reset-password.dto.ts
        │   │   ├── enable-two-factor.dto.ts
        │   │   ├── disable-two-factor.dto.ts
        │   │   ├── verify-two-factor.dto.ts
        │   │   ├── create-role.dto.ts
        │   │   ├── update-role.dto.ts
        │   │   └── filter-role.dto.ts
        │   ├── entities/
        │   │   ├── role.entity.ts              # roles table (UUID PK, soft-delete)
        │   │   ├── permission.entity.ts        # permissions table
        │   │   ├── module.entity.ts            # modules table (grouping permissions)
        │   │   ├── role-permission.entity.ts   # join table: role <-> permission
        │   │   ├── refresh-token.entity.ts     # refresh_tokens (user or admin)
        │   │   └── cache-key.entity.ts         # tracked Redis cache keys per user
        │   ├── guards/
        │   │   ├── jwt-auth.guard.ts           # Validates Bearer JWT
        │   │   ├── roles.guard.ts              # Checks admin role name
        │   │   └── permissions.guard.ts        # Checks granular permission string
        │   ├── interfaces/
        │   │   └── user.interface.ts           # AuthenticatedUser (JWT payload shape)
        │   ├── seeders/
        │   │   └── auth.seeder.ts              # Seeds super-admin, roles, permissions
        │   ├── services/
        │   │   ├── auth.service.ts             # Core login/register/token logic
        │   │   ├── role.service.ts             # Role CRUD + permission assignment
        │   │   └── two-factor.service.ts       # TOTP enable/disable/verify
        │   └── strategies/
        │       └── jwt.strategy.ts             # Passport JWT strategy
        │
        ├── user/                       # End-user management
        │   ├── user.module.ts
        │   ├── controllers/
        │   │   └── user.controller.ts  # Admin CRUD over users
        │   ├── dto/
        │   │   ├── create-user.dto.ts
        │   │   ├── update-user.dto.ts
        │   │   └── filter-user.dto.ts  # Extends PaginationFilterDto
        │   ├── entities/
        │   │   └── user.entity.ts      # users table (UUID, soft-delete, bcrypt hook)
        │   └── services/
        │       └── user.service.ts
        │
        ├── admin/                      # Back-office admin accounts
        │   ├── admin.module.ts
        │   ├── controllers/
        │   │   └── admin.controller.ts
        │   ├── dto/
        │   │   ├── create-admin.dto.ts
        │   │   ├── update-admin.dto.ts
        │   │   └── filter-admin.dto.ts
        │   ├── entities/
        │   │   └── admin.entity.ts     # admins table -> belongs to Role
        │   └── services/
        │       └── admin.service.ts
        │
        ├── activity-log/               # Audit trail for all API actions
        │   ├── activity-log.module.ts
        │   ├── controllers/
        │   │   └── activity-log.controller.ts  # Query logs (admin)
        │   ├── decorators/
        │   │   └── log-activity.decorator.ts   # @LogActivity({ action, resourceType })
        │   ├── dto/
        │   │   └── filter-activity-log.dto.ts
        │   ├── entities/
        │   │   └── activity-log.entity.ts # activity_logs table
        │   ├── interceptors/
        │   │   └── activity-log.interceptor.ts # Global APP_INTERCEPTOR — auto-captures
        │   └── services/
        │       └── activity-log.service.ts
        │
        └── setting/                    # Runtime app configuration (stored in DB)
            ├── setting.module.ts
            ├── controllers/
            │   └── setting.controller.ts   # GET/PUT SMTP and other settings
            ├── dto/
            │   ├── create-smtp-setting.dto.ts
            │   └── smtp-response.dto.ts
            ├── entities/
            │   └── setting.entity.ts       # settings table (key-value store)
            ├── seeders/
            │   └── setting.seeder.ts       # Default SMTP seed
            └── services/
                └── setting.service.ts
```

---

## Architecture Overview

```
                        ┌─────────────────────────────────┐
                        │           HTTP Request            │
                        └────────────────┬────────────────┘
                                         │
                        ┌────────────────▼────────────────┐
                        │        main.ts (bootstrap)        │
                        │  • Helmet (security headers)      │
                        │  • CORS (env-configured origins)  │
                        │  • ValidationPipe (whitelist)     │
                        │  • ClassSerializerInterceptor     │
                        │  • HttpExceptionFilter (global)   │
                        │  • URI Versioning (/v1/)          │
                        └────────────────┬────────────────┘
                                         │
                        ┌────────────────▼────────────────┐
                        │           AppModule               │
                        │  Imports:                         │
                        │  • TypeORM (PostgreSQL)           │
                        │  • Redis CacheModule (global)     │
                        │  • BullModule (job queues)        │
                        │  • ThrottlerModule (rate limit)   │
                        │  • ScheduleModule (cron)          │
                        │  • ConfigModule (global env)      │
                        │  • CommonModule (@Global)         │
                        │  • NotificationModule             │
                        │  • All v1 feature modules         │
                        │  Providers:                       │
                        │  • APP_INTERCEPTOR: ActivityLog   │
                        │  • APP_GUARD: ThrottlerGuard      │
                        └────────────────┬────────────────┘
                                         │
               ┌─────────────────────────┼──────────────────────┐
               │                         │                       │
  ┌────────────▼──────────┐  ┌───────────▼──────────┐  ┌───────▼────────────┐
  │      AuthModule        │  │     FeatureModules    │  │  NotificationModule │
  │                        │  │  • UserModule         │  │                    │
  │  Controllers:          │  │  • AdminModule        │  │  BullMQ Queues:    │
  │  • AuthController      │  │  • ActivityLogModule  │  │  • email-queue     │
  │  • RoleController      │  │  • SettingModule      │  │  • sms-queue       │
  │                        │  │                       │  │                    │
  │  Services:             │  │  Each follows:        │  │  Processors:       │
  │  • AuthService         │  │  Controller ->        │  │  • EmailProcessor  │
  │  • RoleService         │  │  Service ->           │  │  • SmsProcessor    │
  │  • TwoFactorService    │  │  Repository           │  │                    │
  │                        │  │  (TypeORM)            │  │  NotificationSvc   │
  │  Guards:               │  └──────────────────────┘  │  (enqueues jobs)   │
  │  • JwtAuthGuard        │                             └────────────────────┘
  │  • RolesGuard          │
  │  • PermissionsGuard    │
  └────────────────────────┘
```

---

## Request Lifecycle

```
Incoming Request
      │
      ▼
[ThrottlerGuard]            ← Rate limiting (100 req/min, global)
      │
      ▼
[JwtAuthGuard]              ← Validates Bearer token (when @UseGuards applied)
      │
      ▼
[RolesGuard]                ← Checks @Roles() metadata against admin.role
      │
      ▼
[PermissionsGuard]          ← Checks @Permissions() against role.permissions
      │
      ▼
[ActivityLogInterceptor]    ← Pre-captures request metadata
      │
      ▼
Controller Method            ← @CurrentUser() injects JWT payload
      │
      ▼
Service Layer                ← Business logic, TypeORM repositories
      │
      ▼
[ResponseInterceptor]       ← Wraps result in { success, data, message }
      │
      ▼
[HttpExceptionFilter]       ← Catches errors → standardised error response
      │
      ▼
JSON Response
```

---

## Database Entity Relationships

```
modules ──────────────────────┐
                               │ 1:N
permissions (module_id) ───────┘
       │ N:M (via role_permissions)
roles ─┤
       │ 1:N
admins ┘
       └── refresh_tokens (adminId)

users ──── refresh_tokens (userId)
      └─── cache_keys
      └─── user_activity_logs

settings  (key-value store — SMTP config, etc.)
```

---

## Authentication Flows

### Admin Login

```
POST /api/v1/auth/admin-login
  → validate credentials (bcrypt)
  → check 2FA if enabled
  → issue accessToken (JWT) + refreshToken (DB)
  → return tokens + admin profile
```

### User Registration (OTP multi-step)

```
1. POST /api/v1/auth/user-register-otp-request    → send SMS OTP
2. POST /api/v1/auth/user-register-otp-verify     → verify OTP  → stage: passwordSetup
3. POST /api/v1/auth/user-register-password-setup → set password → stage: accountSetup
4. POST /api/v1/auth/user-register-account-setup  → profile + photo upload → complete
```

### Token Refresh

```
POST /api/v1/auth/refresh  { refreshToken }
  → validates token in DB (not revoked, not expired)
  → issues new accessToken
```

### Social Login (Google / Apple)

```
POST /api/v1/auth/user/google-login  { idToken }
POST /api/v1/auth/user/apple-login   { idToken }
  → verify token with provider
  → upsert user (googleId / appleId)
  → return JWT pair
```

### Password Reset

```
Admin:
  POST /api/v1/auth/otp/send/forgot-password     → send OTP to email
  POST /api/v1/auth/otp/verify/forgot-password   → verify OTP → reset token
  POST /api/v1/auth/reset-password               → set new password

User:
  POST /api/v1/auth/user/otp/send/forgot-password    → send OTP to phone (SMS)
  POST /api/v1/auth/user/otp/verify/forgot-password  → verify OTP → reset token
  POST /api/v1/auth/user/reset-password              → set new password
```

---

## Key Conventions

| Convention       | Detail                                                                                |
| ---------------- | ------------------------------------------------------------------------------------- |
| Primary keys     | `uuid` generated via `uuidv4()` in `@BeforeInsert`                                    |
| Soft deletes     | `@DeleteDateColumn()` on all main entities                                            |
| Password hashing | `@BeforeInsert` / `@BeforeUpdate` hook with bcrypt; skips if already hashed           |
| Response shape   | Always `{ success, data, message, meta? }` via `ResponseUtil` + `ResponseInterceptor` |
| Pagination       | Extend `PaginationFilterDto` (page, limit, sort) in all filter DTOs                   |
| Activity logging | Decorate controller methods with `@LogActivity({ action, resourceType })`             |
| File uploads     | Multer `memoryStorage` → streamed to S3; key stored in DB; served via presigned URL   |
| Notifications    | Never send inline — always enqueue via `NotificationService` to BullMQ                |
| Env config       | All secrets accessed via `ConfigService`; never `process.env` directly in services    |
| SMTP config      | Stored in `settings` DB table — editable at runtime without redeployment              |

---

## npm Scripts Reference

```bash
# Development
npm run start:dev           # Dev server with watch mode
npm run start:debug         # Dev server with debugger

# Build
npm run build               # Production build (SWC)
npm run build:low-mem       # Production build with 1536MB memory cap

# Database
npm run migration:generate  # Generate migration from entity changes
npm run migration:run       # Apply pending migrations
npm run migration:revert    # Roll back last migration
npm run migration:run:prod  # Run migrations against compiled dist

npm run db:seed             # Seed roles, permissions, super-admin, settings
npm run db:clear            # Truncate seed data
npm run db:reset            # db:clear + db:seed

# Testing
npm run test                # Unit tests
npm run test:watch          # Unit tests with watch mode
npm run test:cov            # Unit tests with coverage report
npm run test:e2e            # End-to-end tests

# Code Quality
npm run lint                # ESLint with auto-fix
npm run format              # Prettier format
```

---

## Environment Variables

Copy `.env.example` to `.env` and fill in the values.

```bash
PORT=3000

# Database (PostgreSQL)
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=postgres
DB_PASSWORD=secret
DB_NAME=app_db

# JWT
JWT_SECRET=your-jwt-secret
JWT_EXPIRATION=172800000        # milliseconds (default: 48h)
AUTH_PASSWORD_SALT_ROUNDS=10

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# AWS S3
AWS_REGION=
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_S3_BUCKET=

# CORS (comma-separated origins; use * or all to allow everything)
CORS_ORIGINS=http://localhost:3001,https://yourdomain.com
```

---

## Getting Started

```bash
# 1. Install dependencies
npm install

# 2. Copy and configure environment
cp .env.example .env

# 3. Run database migrations
npm run migration:run

# 4. Seed initial data (roles, permissions, super-admin)
npm run db:seed

# 5. Start the development server
npm run start:dev
```

The API will be available at `http://localhost:3000/api/v1/`.

---

## License

MIT
