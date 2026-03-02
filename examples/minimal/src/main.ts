import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(3000);
  console.log('Example app: http://localhost:3000');
  console.log('POST /auth/login  { "email": "user@example.com", "password": "Password123!" }');
  console.log('POST /auth/refresh  { "refreshToken": "<token>" }');
  console.log('GET /profile  Header: Authorization: Bearer <accessToken>');
}
bootstrap();
