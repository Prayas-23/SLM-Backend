export enum AIOperation {
  LIST = 'LIST',
  COUNT = 'COUNT',
  SUMMARY = 'SUMMARY',
  EXPLAIN = 'EXPLAIN',
  ANALYZE = 'ANALYZE',
  COMPARE = 'COMPARE',
  HELP = 'HELP',
  UNKNOWN = 'UNKNOWN',
}

export enum AIEntity {
  VULNERABILITY = 'VULNERABILITY',
  SECURITY_REQUEST = 'SECURITY_REQUEST',
  APPLICATION = 'APPLICATION',
  INFRASTRUCTURE_ASSET = 'INFRASTRUCTURE_ASSET',
  CONTINUOUS_SCAN_FINDING = 'CONTINUOUS_SCAN_FINDING',
  CLOUD_RESOURCE = 'CLOUD_RESOURCE',
  DASHBOARD = 'DASHBOARD',
  REPORT = 'REPORT',
  GENERAL_SECURITY = 'GENERAL_SECURITY',
  UNKNOWN = 'UNKNOWN',
}

export interface IntentFilters {
  severity?: string;
  status?: string;
  source?: string;
  environment?: string;
  application?: string;
  asset?: string;
  owner?: string;
  assignee?: string;
  dateRange?: string;
  requestId?: string;
  vulnerabilityId?: string;
  [key: string]: string | undefined;
}

export interface IntentDto {
  operation: AIOperation;
  entity: AIEntity;
  filters: IntentFilters;
  confidence: number;
}
