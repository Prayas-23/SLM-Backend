import { Injectable } from '@nestjs/common';
import { IntentDto, AIEntity, AIOperation, IntentFilters } from '../dto/intent.dto';

/**
 * SuggestionService
 *
 * Generates contextual follow-up suggestions based on the current intent.
 * Suggestions are deterministic and entity/operation-aware — not LLM-generated.
 *
 * Design: Structured suggestion tables per entity.
 * Adding new entities = adding a new case block.
 * No hardcoded mega-list. Each entity has a focused, contextual set.
 */
@Injectable()
export class SuggestionService {

  generate(intent: IntentDto): string[] {
    const { entity, operation, filters } = intent;

    const base = this.entitySuggestions(entity, operation, filters);
    const contextual = this.filterContextSuggestions(filters);

    // Merge, deduplicate, limit to 5
    return [...new Set([...contextual, ...base])].slice(0, 5);
  }

  // ── Entity-level suggestions ─────────────────────────────────────────────────

  private entitySuggestions(entity: AIEntity, operation: AIOperation, filters: IntentFilters): string[] {
    switch (entity) {
      case AIEntity.VULNERABILITY:
        return this.vulnerabilitySuggestions(operation, filters);
      case AIEntity.SECURITY_REQUEST:
        return this.securityRequestSuggestions(operation);
      case AIEntity.APPLICATION:
        return ['Show vulnerabilities in my applications', 'Count security requests by application', 'List high-risk applications'];
      case AIEntity.INFRASTRUCTURE_ASSET:
        return ['Show CVS findings for this asset', 'Count vulnerabilities in production infrastructure', 'List critical infrastructure assets'];
      case AIEntity.CONTINUOUS_SCAN_FINDING:
        return ['Show unassigned CVS findings', 'Count critical CVS findings', 'Show accepted findings this month'];
      case AIEntity.CLOUD_RESOURCE:
        return ['Show cloud resources by provider', 'Count resources in production', 'List AWS cloud resources'];
      case AIEntity.DASHBOARD:
        return ['Show critical vulnerabilities', 'Summarize security requests', 'Analyze SLA breaches'];
      case AIEntity.GENERAL_SECURITY:
        return ['Explain CVSS scoring', 'Explain OWASP Top 10', 'Explain SQL Injection', 'Explain CWE-79', 'How does VAPT work?'];
      default:
        return ['What can Sentinel AI do?', 'Show critical vulnerabilities', 'Summarize security posture'];
    }
  }

  private vulnerabilitySuggestions(operation: AIOperation, filters: IntentFilters): string[] {
    const suggestions: string[] = [];

    if (operation !== AIOperation.COUNT) suggestions.push('How many vulnerabilities match these filters?');
    if (operation !== AIOperation.SUMMARY) suggestions.push('Summarize the security posture');
    if (!filters.severity)    suggestions.push('Show only CRITICAL vulnerabilities');
    if (!filters.status)      suggestions.push('Show only OPEN vulnerabilities');
    if (!filters.environment) suggestions.push('Show only Production vulnerabilities');
    if (filters.severity === 'CRITICAL') suggestions.push('Show HIGH severity vulnerabilities');
    suggestions.push('Show SLA-breached vulnerabilities');
    suggestions.push('Compare Production vs Pre-Production vulnerabilities');

    return suggestions;
  }

  private securityRequestSuggestions(operation: AIOperation): string[] {
    const suggestions: string[] = [];
    if (operation !== AIOperation.COUNT) suggestions.push('How many security requests are there?');
    suggestions.push('Show VAPT security requests', 'Show IN_PROGRESS requests', 'Count requests by source');
    return suggestions;
  }

  // ── Filter-context suggestions ───────────────────────────────────────────────

  private filterContextSuggestions(filters: IntentFilters): string[] {
    const s: string[] = [];
    if (filters.severity === 'CRITICAL') s.push('Show unassigned CRITICAL findings');
    if (filters.environment === 'PRODUCTION') s.push('Compare Production vs Pre-Production');
    if (filters.source === 'VAPT') s.push('Show Bug Bounty vulnerabilities');
    return s;
  }
}
