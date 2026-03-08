import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(cookieParser());
  // Optional CORS config if frontend on different domain
  // app.enableCors({
  //   // origin: 'https://latodo-xi.vercel.app', // your frontend URL
  //   // origin: 'http://localhost:5173', // your frontend URL
  //   // credentials: true, // allow cookies to be sent
  // });
  // app.useGlobalPipes(
  //   new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }),
  // );
  app.useGlobalPipes(new ValidationPipe({ whitelist: true }));
  await app.listen(process.env.PORT ?? 3000);
}
void bootstrap();
