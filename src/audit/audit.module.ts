import { Module } from '@nestjs/common';

/**
 * Audit Module
 * Planned: Immutable audit trail for all entity mutations,
 * actor/action/timestamp/diff logging, async BullMQ queue flush.
 */
@Module({})
export class AuditModule {}
