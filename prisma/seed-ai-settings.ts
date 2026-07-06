import { PrismaClient, SettingCategory, SettingDataType } from '@prisma/client';

const prisma = new PrismaClient();

/**
 * Seeds the AI PlatformSetting rows required for AIService to initialize.
 * Run this script once after adding AI to the SettingCategory enum:
 *
 *   npx ts-node prisma/seed-ai-settings.ts
 *
 * All rows are created with upsert so re-running is safe.
 */
async function main() {
  const AI_SETTINGS = [
    {
      key:         'ai.enabled',
      value:       'false',
      dataType:    SettingDataType.BOOLEAN,
      label:       'AI Enabled',
      description: 'Master switch to enable or disable all AI features platform-wide.',
      isEditable:  true,
    },
    {
      key:         'ai.provider',
      value:       'GEMINI',
      dataType:    SettingDataType.STRING,
      label:       'AI Provider',
      description: 'LLM provider to use. Supported: GEMINI. Future: OPENAI, CLAUDE, AZURE, OLLAMA.',
      isEditable:  true,
    },
    {
      key:         'ai.apiKey',
      value:       '',
      dataType:    SettingDataType.STRING,
      label:       'API Key',
      description: 'Provider API key. Never returned to the frontend in plain text.',
      isEditable:  true,
    },
    {
      key:         'ai.model',
      value:       'gemini-2.0-flash',
      dataType:    SettingDataType.STRING,
      label:       'Model',
      description: 'Model identifier. e.g. gemini-2.0-flash, gemini-1.5-pro',
      isEditable:  true,
    },
    {
      key:         'ai.temperature',
      value:       '0.2',
      dataType:    SettingDataType.STRING,
      label:       'Temperature',
      description: 'Sampling temperature (0.0 – 1.0). Lower = more deterministic.',
      isEditable:  true,
    },
    {
      key:         'ai.maxTokens',
      value:       '1024',
      dataType:    SettingDataType.INTEGER,
      label:       'Max Tokens',
      description: 'Maximum output tokens per response.',
      isEditable:  true,
    },
    {
      key:         'ai.timeoutMs',
      value:       '30000',
      dataType:    SettingDataType.INTEGER,
      label:       'Request Timeout (ms)',
      description: 'HTTP request timeout for LLM calls in milliseconds.',
      isEditable:  true,
    },
  ];

  console.log('Seeding AI PlatformSettings...');

  for (const setting of AI_SETTINGS) {
    await prisma.platformSetting.upsert({
      where:  { key: setting.key },
      create: { category: SettingCategory.AI, ...setting },
      update: { label: setting.label, description: setting.description },
    });
    console.log(`  ✓ ${setting.key}`);
  }

  console.log('AI settings seeded successfully.');
}

main()
  .catch((e) => { console.error(e); process.exit(1); })
  .finally(() => prisma.$disconnect());
