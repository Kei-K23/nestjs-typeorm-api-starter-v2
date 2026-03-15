# Pann Thee Backend

## Tech Stack

- NodeJS, NestJS
- TypeScript
- PostgreSQL
- TypeORM

<!--
InternalServerErrorException: Invalid SMS provider response: {"channel":"SMS","requestId":null,"to":"095085230","createdAt":{"expression":"NOW()","params":[]},"expireAt":"2026-03-09 09:54:27"}
    at SMSPhoServiceUtils.sendOTP (/Users/arkarmin/Desktop/OBS/pann-thee-backend/src/common/utils/sms-pho-service.utils.ts:74:15)
    at process.processTicksAndRejections (node:internal/process/task_queues:105:5)
    at async AuthService.userRegisterOTPRequest (/Users/arkarmin/Desktop/OBS/pann-thee-backend/src/v1/auth/services/auth.service.ts:219:36)
    at async AuthController.userRegisterOTPRequest (/Users/arkarmin/Desktop/OBS/pann-thee-backend/src/v1/auth/controllers/auth.controller.ts:69:20) {
  response: {
    message: 'Invalid SMS provider response: {"channel":"SMS","requestId":null,"to":"095085230","createdAt":{"expression":"NOW()","params":[]},"expireAt":"2026-03-09 09:54:27"}',
    error: 'Internal Server Error',
    statusCode: 500
  },
  status: 500,
  options: {}
}
[Pann Thee Backend] 58272 3/9/2026, 9:24:27 AM   ERROR [HttpExceptionFilter] HTTP Exception: Invalid SMS provider response: {"channel":"SMS","requestId":null,"to":"095085230","createdAt":{"expression":"NOW()","params":[]},"expireAt":"2026-03-09 09:54:27"} - {
  stack: [
    'InternalServerErrorException: Invalid SMS provider response: {"channel":"SMS","requestId":null,"to":"095085230","createdAt":{"expression":"NOW()","params":[]},"expireAt":"2026-03-09 09:54:27"}\n' +
      '    at SMSPhoServiceUtils.sendOTP (/Users/arkarmin/Desktop/OBS/pann-thee-backend/src/common/utils/sms-pho-service.utils.ts:74:15)\n' +
      '    at process.processTicksAndRejections (node:internal/process/task_queues:105:5)\n' +
      '    at async AuthService.userRegisterOTPRequest (/Users/arkarmin/Desktop/OBS/pann-thee-backend/src/v1/auth/services/auth.service.ts:219:36)\n' +
      '    at async AuthController.userRegisterOTPRequest (/Users/arkarmin/Desktop/OBS/pann-thee-backend/src/v1/auth/controllers/auth.controller.ts:69:20)'
  ]
} -->
