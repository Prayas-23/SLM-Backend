import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Global API prefix
  app.setGlobalPrefix('api/v1');

  // Swagger UI
  const config = new DocumentBuilder()
    .setTitle('Sentinel SLM Platform API')
    .setDescription(
      'REST API for Sentinel\'s Security & License Management (SLM) platform.\n\n' +
      'Base path: `/api/v1` (see below)',
    )
    .setVersion('1.0')
    .addBearerAuth()  // JWT auth support
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('docs', app, document);

  // Global validation pipe — enforces all DTOs automatically
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,          // strip unknown properties
      forbidNonWhitelisted: true,
      transform: true,          // auto-transform payloads to DTO class instances
    }),
  );

  // CORS — allow frontend dev server
  app.enableCors({
    origin: process.env.FRONTEND_URL || 'http://localhost:5173',
    credentials: true,
  });



  const port = process.env.PORT || 3000;
  await app.listen(port);
  console.log(`Sentinel SLM Backend running on http://localhost:${port}/api/v1`);
}

bootstrap();
