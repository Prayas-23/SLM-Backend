import { Injectable } from '@nestjs/common';
import { IntentDto, AIOperation, AIEntity } from '../dto/intent.dto';
import { QueryResult } from '../query/query-result.dto';
import { SEARCH_SYSTEM_PROMPT } from './system.prompt';
import { LIST_PROMPT }    from './task-prompts/list.prompt';
import { COUNT_PROMPT }   from './task-prompts/count.prompt';
import { SUMMARY_PROMPT } from './task-prompts/summary.prompt';
import { ANALYZE_PROMPT } from './task-prompts/analyze.prompt';
import { COMPARE_PROMPT } from './task-prompts/compare.prompt';
import { EXPLAIN_PROMPT } from './task-prompts/explain.prompt';
import { HELP_PROMPT }    from './task-prompts/help.prompt';

/**
 * PromptBuilderService
 *
 * The ONLY component allowed to assemble prompts for Gemini.
 *
 * Prompt structure (every request):
 *   SYSTEM_PROMPT → TASK_PROMPT → VERIFIED_DATA → USER_QUESTION
 *
 * What is NEVER included:
 *   - SQL queries
 *   - Prisma code
 *   - JWT tokens
 *   - API keys
 *   - DB credentials
 *   - Raw Prisma objects (data is serialized to plain text)
 *
 * Architecture note:
 *   The system prompt and task prompts are versioned separately.
 *   Adding a new task = new file in task-prompts/ + one case here.
 */
@Injectable()
export class PromptBuilderService {

  // ── Public API ──────────────────────────────────────────────────────────────

  /**
   * Assembles the system prompt string (constant for all search requests).
   */
  getSystemPrompt(): string {
    return SEARCH_SYSTEM_PROMPT;
  }

  /**
   * Assembles the user-turn message from: task prompt + conversation context + verified data + question.
   *
   * New prompt order (Phase 3):
   *   TASK_PROMPT → CONVERSATION_CONTEXT → VERIFIED_DATA → USER_QUESTION
   *
   * For GENERAL_SECURITY / EXPLAIN: no QueryResult is required.
   * For all other entities: QueryResult is injected as verified data.
   * conversationContext: plain-text string from ContextBuilderService (empty = no history).
   */
  buildUserPrompt(
    intent:              IntentDto,
    userQuery:           string,
    result?:             QueryResult,
    conversationContext?: string,
  ): string {
    const taskPrompt = this.selectTaskPrompt(intent.operation);
    const dataSection = this.serializeQueryResult(intent, result);

    const parts: string[] = [taskPrompt, '', '---', ''];

    if (conversationContext && conversationContext.trim().length > 0) {
      parts.push(conversationContext, '---', '');
    }

    parts.push('USER QUESTION:', userQuery, '', dataSection);

    return parts.join('\n');
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  private selectTaskPrompt(operation: AIOperation): string {
    const prompts: Record<AIOperation, string> = {
      [AIOperation.LIST]:    LIST_PROMPT,
      [AIOperation.COUNT]:   COUNT_PROMPT,
      [AIOperation.SUMMARY]: SUMMARY_PROMPT,
      [AIOperation.ANALYZE]: ANALYZE_PROMPT,
      [AIOperation.COMPARE]: COMPARE_PROMPT,
      [AIOperation.EXPLAIN]: EXPLAIN_PROMPT,
      [AIOperation.HELP]:    HELP_PROMPT,
      [AIOperation.UNKNOWN]: HELP_PROMPT, // fallback
    };
    return prompts[operation] ?? HELP_PROMPT;
  }

  /**
   * Converts QueryResult into plain-text context for Gemini.
   *
   * Rules:
   * - Only include fields required for explanation.
   * - Never dump raw Prisma objects.
   * - Large result sets are summarized, not fully listed.
   */
  private serializeQueryResult(
    intent: IntentDto,
    result?: QueryResult,
  ): string {
    // GENERAL_SECURITY and EXPLAIN with no data: Gemini uses its own knowledge
    if (!result || intent.entity === AIEntity.GENERAL_SECURITY) {
      return '(No platform data required — use cybersecurity knowledge only.)';
    }

    if (!result.success) {
      return `VERIFIED DATA:\nQuery failed: ${result.error ?? 'Unknown error'}`;
    }

    if (result.totalRecords === 0) {
      return [
        'VERIFIED DATA:',
        `No records found matching the specified filters.`,
        `Entity: ${result.entity}`,
        `Filters applied: ${this.serializeFilters(intent)}`,
      ].join('\n');
    }

    const lines: string[] = [
      'VERIFIED DATA:',
      `Entity:    ${result.entity}`,
      `Operation: ${result.operation}`,
      `Total:     ${result.totalRecords} records`,
      `Filters:   ${this.serializeFilters(intent)}`,
      '',
    ];

    // For LIST operations: summarize up to 10 records (token efficiency)
    if (intent.operation === AIOperation.LIST) {
      const preview = result.data.slice(0, 10);
      lines.push(`Showing ${preview.length} of ${result.totalRecords} records:`);
      preview.forEach((row, i) => {
        lines.push(`${i + 1}. ${this.summarizeRecord(intent.entity, row)}`);
      });
      if (result.totalRecords > 10) {
        lines.push(`... and ${result.totalRecords - 10} more.`);
      }
    } else {
      // For COUNT / SUMMARY / ANALYZE / COMPARE: inject the full structured result
      result.data.forEach((row) => {
        lines.push(this.flattenMetrics(row));
      });
    }

    return lines.join('\n');
  }

  private serializeFilters(intent: IntentDto): string {
    const entries = Object.entries(intent.filters).filter(([, v]) => v !== undefined && v !== null);
    if (entries.length === 0) return 'None';
    return entries.map(([k, v]) => `${k}=${v}`).join(', ');
  }

  /**
   * Produces a one-line human-readable summary of a single record.
   * Only includes fields that are safe and meaningful for an LLM to reason about.
   * Never dumps the raw Prisma row.
   */
  private summarizeRecord(entity: AIEntity, row: unknown): string {
    const r = row as Record<string, unknown>;

    switch (entity) {
      case AIEntity.VULNERABILITY:
        return [
          r['vulnId'],
          r['severity'],
          r['status'],
          r['shortDesc'],
          r['source'],
          r['assignedTo'] ? `(Assigned: ${(r['assignedTo'] as Record<string, unknown>)['name']})` : '(Unassigned)',
        ].filter(Boolean).join(' | ');

      case AIEntity.SECURITY_REQUEST:
        return [
          r['reqId'],
          r['source'],
          r['status'],
          r['environment'],
          r['targetApp'] ? `App: ${(r['targetApp'] as Record<string, unknown>)['name']}` : '',
        ].filter(Boolean).join(' | ');

      case AIEntity.APPLICATION:
        return [
          r['appId'],
          r['name'],
          r['environment'],
          r['criticality'],
          r['vaptStatus'],
        ].filter(Boolean).join(' | ');

      case AIEntity.INFRASTRUCTURE_ASSET:
        return [
          r['serverId'],
          r['serverName'],
          r['type'],
          r['environment'],
          r['criticality'],
        ].filter(Boolean).join(' | ');

      case AIEntity.CONTINUOUS_SCAN_FINDING:
        return [
          r['vulnTitle'],
          r['severity'],
          r['status'],
          r['assetName'],
          r['assignedOwnerName'] || '(Unassigned)',
        ].filter(Boolean).join(' | ');

      case AIEntity.CLOUD_RESOURCE:
        return [
          r['resourceId'],
          r['resourceName'],
          r['cloudProvider'],
          r['type'],
          r['status'],
          r['environment'],
        ].filter(Boolean).join(' | ');

      default:
        return JSON.stringify(r).substring(0, 150);
    }
  }

  /**
   * Converts aggregate/metric rows into a human-readable block.
   * Used for COUNT, SUMMARY, ANALYZE, COMPARE, DASHBOARD.
   */
  private flattenMetrics(row: unknown): string {
    const r = row as Record<string, unknown>;
    return Object.entries(r)
      .filter(([, v]) => v !== null && v !== undefined)
      .map(([k, v]) => {
        if (Array.isArray(v)) {
          const items = (v as Array<Record<string, unknown>>)
            .map((item) => {
              const key = Object.keys(item).find((k2) => k2 !== '_count') ?? '';
              const count = (item['_count'] as number | undefined) ?? '';
              return `  - ${item[key]}: ${count}`;
            })
            .join('\n');
          return `${k}:\n${items}`;
        }
        return `${k}: ${String(v)}`;
      })
      .join('\n');
  }
}
