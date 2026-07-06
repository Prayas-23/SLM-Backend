// =============================================================================
// Sentinel SLM — Production Seed Script
// Imports every frontend mock entity (apps.ts, bb.ts, cloud.ts, cs.ts, cvs.ts,
// infra.ts, requests.ts, rt.ts, vapt.ts, vulnerabilities.ts) into PostgreSQL
// via the Prisma schema, preserving relationships, history, and lifecycle data.
// =============================================================================

import {
  PrismaClient,
  UserRole,
  RequestSource,
  RequestStatus,
  VulnerabilityStatus,
  Severity,
  Environment,
  AssetType,
  InfraType,
  CloudProvider,
  CloudResourceType,
  AuditAction,
  AuditEntityType,
  SettingCategory,
  SettingDataType,
  type Application,
  type InfrastructureAsset,
  type User,
} from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

// -----------------------------------------------------------------------------
// Small helpers
// -----------------------------------------------------------------------------

/** Parse mock dates like "Mar 14, 2026" / "May 03, 2026" into Date objects. */
function d(dateStr: string): Date {
  return new Date(dateStr);
}

/** Parse a percentage string like "78%" into an integer (78). */
function pct(value: string): number {
  const n = parseInt(value.replace('%', '').trim(), 10);
  return Number.isNaN(n) ? 100 : n;
}

/** Map frontend severity strings to the Severity enum. */
function mapSeverity(value: string): Severity {
  switch (value) {
    case 'Critical':
      return Severity.CRITICAL;
    case 'High':
      return Severity.HIGH;
    case 'Medium':
      return Severity.MEDIUM;
    case 'Low':
      return Severity.LOW;
    default:
      return Severity.INFORMATIONAL;
  }
}

/** Map frontend vulnerability status strings to the 6-state VulnerabilityStatus enum. */
function mapVulnStatus(value: string): VulnerabilityStatus {
  switch (value) {
    case 'Open':
      return VulnerabilityStatus.OPEN;
    case 'Assigned':
      return VulnerabilityStatus.ASSIGNED;
    case 'In Progress':
    case 'Patching':
      return VulnerabilityStatus.IN_PROGRESS;
    case 'Patched':
      return VulnerabilityStatus.PATCHED;
    case 'Revalidating':
    case 'Pending Revalidation':
      return VulnerabilityStatus.PENDING_REVALIDATION;
    case 'Closed':
      return VulnerabilityStatus.CLOSED;
    default:
      return VulnerabilityStatus.OPEN;
  }
}

/** Map frontend request status strings to the RequestStatus enum. */
function mapRequestStatus(value: string): RequestStatus {
  switch (value) {
    case 'Open':
      return RequestStatus.OPEN;
    case 'Submitted':
      return RequestStatus.SUBMITTED;
    case 'In Progress':
      return RequestStatus.IN_PROGRESS;
    case 'Patching':
      return RequestStatus.PATCHING;
    case 'Revalidation':
    case 'Revalidating':
      return RequestStatus.REVALIDATION;
    case 'Closed':
      return RequestStatus.CLOSED;
    case 'Active':
      return RequestStatus.ACTIVE;
    default:
      return RequestStatus.OPEN;
  }
}

/** Map frontend app "type" strings to AssetType. */
function mapAssetType(value: string): AssetType {
  if (value.includes('API')) return AssetType.API;
  return AssetType.WEB_APPLICATION;
}

/** Map frontend infra "source" (On-Premise/AWS/Azure) + role into an InfraType best-guess. */
function mapInfraType(role: string, os: string): InfraType {
  const r = role.toLowerCase();
  const o = os.toLowerCase();
  if (r.includes('firewall') || r.includes('router')) return InfraType.FIREWALL;
  if (r.includes('kubernetes') || o.includes('eks') || r.includes('cluster')) return InfraType.CONTAINER_CLUSTER;
  if (r.includes('database') || r.includes('db')) return InfraType.DATABASE_SERVER;
  if (o.includes('azure') || r.includes('runner')) return InfraType.VIRTUAL_MACHINE;
  return InfraType.PHYSICAL_SERVER;
}

/** Map "Prod"/"Production"/"Non-Prod"/"Pre-Production" style strings to Environment. */
function mapEnvironment(value: string): Environment {
  const v = value.toLowerCase();
  if (v.includes('non-prod') || v.includes('development') || v.includes('dev')) {
    // "Non-Prod" in infra.ts inventory is used for the CI/CD runner pool, which is
    // functionally a development/build environment.
    return v.includes('pre') ? Environment.PRE_PRODUCTION : Environment.DEVELOPMENT;
  }
  if (v.includes('pre-prod') || v.includes('preprod') || v.includes('uat')) return Environment.PRE_PRODUCTION;
  return Environment.PRODUCTION;
}

async function main() {
  console.log('🌱 Seeding Sentinel SLM from frontend mock data...');
  const hash = await bcrypt.hash('Sentinel@2024', 10);

  // ===========================================================================
  // USERS
  // Identified across apps.ts (owners), infra.ts (asset owners), cs.ts/rt.ts
  // (security lead actor), and the platform role baseline from the original seed.
  // ===========================================================================

  const userDefs: Array<{
    email: string;
    name: string;
    staffId: string;
    department: string;
    role: UserRole;
  }> = [
      // Security Lead — appears as "Aanya Sharma (Security Lead)" in cs.ts / rt.ts
      // comments and log actors, and is also the owner of payments-api / billing-portal.
      { email: 'aanya.sharma@msil.in', name: 'Aanya Sharma', staffId: 'EMP-1101', department: 'Finance IT', role: UserRole.SECURITY_LEAD },
      // Application Owners
      { email: 'rohit.sharma@msil.in', name: 'Rohit Sharma', staffId: 'EMP-4210', department: 'Platform', role: UserRole.APPLICATION_OWNER },
      { email: 'meera.krishnan@msil.in', name: 'Meera Krishnan', staffId: 'EMP-0712', department: 'Security', role: UserRole.APPLICATION_OWNER },
      { email: 'priya.verma@msil.in', name: 'Priya Verma', staffId: 'EMP-2801', department: 'Analytics', role: UserRole.APPLICATION_OWNER },
      { email: 'jai.tiwari@msil.in', name: 'Jai Tiwari', staffId: 'EMP-5301', department: 'Risk & Compliance', role: UserRole.APPLICATION_OWNER },
      { email: 'suresh.nair@msil.in', name: 'Suresh Nair', staffId: 'EMP-6101', department: 'IT Ops', role: UserRole.APPLICATION_OWNER },
      // Infrastructure Owners
      { email: 'vijay.mehta@msil.in', name: 'Vijay Mehta', staffId: 'EMP-3301', department: 'Network Security', role: UserRole.INFRASTRUCTURE_OWNER },
      { email: 'kiran.dev@msil.in', name: 'Kiran Dev', staffId: 'EMP-4101', department: 'DevOps', role: UserRole.INFRASTRUCTURE_OWNER },
      // Baseline platform roles not otherwise represented in the mock data, kept so
      // every UserRole value has at least one seeded account.
      { email: 'analyst@sentinel.local', name: 'Priya Sharma', staffId: 'SLM-002', department: 'Security', role: UserRole.SECURITY_ANALYST },
      { email: 'readonly@sentinel.local', name: 'Vikram Das', staffId: 'SLM-005', department: 'Audit', role: UserRole.READ_ONLY },
    ];

  const users: Record<string, User> = {};
  for (const u of userDefs) {
    users[u.email] = await prisma.user.upsert({
      where: { email: u.email },
      update: { name: u.name, staffId: u.staffId, department: u.department, role: u.role },
      create: {
        email: u.email,
        name: u.name,
        staffId: u.staffId,
        department: u.department,
        passwordHash: hash,
        role: u.role,
        isActive: true,
      },
    });
  }
  const aanya = users['aanya.sharma@msil.in'];
  const rohit = users['rohit.sharma@msil.in'];
  const meera = users['meera.krishnan@msil.in'];
  const priyaV = users['priya.verma@msil.in'];
  const jai = users['jai.tiwari@msil.in'];
  const suresh = users['suresh.nair@msil.in'];
  const vijay = users['vijay.mehta@msil.in'];
  const kiranDev = users['kiran.dev@msil.in'];
  const analyst = users['analyst@sentinel.local'];

  console.log(`✅ Users (${Object.keys(users).length})`);

  // ===========================================================================
  // APPLICATIONS — apps.ts: mockAppSummaries / mockAppDetails / mockAppInventory
  // All 7 inventory apps are seeded; legacy-erp and payments-api carry full detail.
  // ===========================================================================

  const apps: Record<string, Application> = {};

  apps['legacy-erp'] = await prisma.application.upsert({
    where: { appId: 'APP-0042' },
    update: {
      name: 'legacy-erp',
      description: 'Enterprise Resource Planning system for plant and operations management',
      type: AssetType.WEB_APPLICATION,
      environment: Environment.PRODUCTION,
      department: 'Platform',
      classification: 'Internal',
      criticality: 'Critical',
      ownerId: rohit.id,
      ownerEmail: 'rohit.sharma@msil.in',
      internetAccessible: false,
      piiData: true,
      biaApp: true,
      prodUrl: 'erp.msil.internal',
      preprodUrl: 'https://uat-erp.msil.internal/',
      devUrl: 'https://dev-erp.msil.internal/',
      vaptStatus: 'Overdue',
      lastVaptDate: d('Oct 01, 2024'),
      nextVaptDate: d('Apr 22, 2026'),
      registeredOn: d('Jan 12, 2023'),

    },
    create: {
      appId: 'APP-0042',
      name: 'legacy-erp',
      description: 'Enterprise Resource Planning system for plant and operations management',
      type: AssetType.WEB_APPLICATION,
      environment: Environment.PRODUCTION,
      department: 'Platform',
      classification: 'Internal',
      criticality: 'Critical',
      ownerId: rohit.id,
      ownerEmail: 'rohit.sharma@msil.in',
      internetAccessible: false,
      piiData: true,
      biaApp: true,
      prodUrl: 'erp.msil.internal',
      preprodUrl: 'https://uat-erp.msil.internal/',
      devUrl: 'https://dev-erp.msil.internal/',
      vaptStatus: 'Overdue',
      lastVaptDate: d('Oct 01, 2024'),
      nextVaptDate: d('Apr 22, 2026'),
      registeredOn: d('Jan 12, 2023'),

    },
  });

  apps['payments-api'] = await prisma.application.upsert({
    where: { appId: 'APP-0011' },
    update: {
      name: 'payments-api',
      description: 'Core payment processing API handling all MSIL transaction and reconciliation flows',
      type: AssetType.API,
      environment: Environment.PRODUCTION,
      department: 'Finance IT',
      classification: 'Internet Facing',
      criticality: 'Critical',
      ownerId: aanya.id,
      ownerEmail: 'aanya.sharma@msil.in',
      internetAccessible: true,
      piiData: true,
      biaApp: true,
      prodUrl: 'api.payments.msil.in',
      preprodUrl: 'https://uat-payments.msil.internal/',
      devUrl: 'https://dev-payments.msil.internal/',
      vaptStatus: 'Scheduled',
      lastVaptDate: d('Feb 17, 2026'),
      nextVaptDate: d('Aug 01, 2026'),
      registeredOn: d('Mar 05, 2022'),

    },
    create: {
      appId: 'APP-0011',
      name: 'payments-api',
      description: 'Core payment processing API handling all MSIL transaction and reconciliation flows',
      type: AssetType.API,
      environment: Environment.PRODUCTION,
      department: 'Finance IT',
      classification: 'Internet Facing',
      criticality: 'Critical',
      ownerId: aanya.id,
      ownerEmail: 'aanya.sharma@msil.in',
      internetAccessible: true,
      piiData: true,
      biaApp: true,
      prodUrl: 'api.payments.msil.in',
      preprodUrl: 'https://uat-payments.msil.internal/',
      devUrl: 'https://dev-payments.msil.internal/',
      vaptStatus: 'Scheduled',
      lastVaptDate: d('Feb 17, 2026'),
      nextVaptDate: d('Aug 01, 2026'),
      registeredOn: d('Mar 05, 2022'),

    },
  });

  apps['auth-service'] = await prisma.application.upsert({
    where: { appId: 'APP-0007' },
    update: {
      name: 'auth-service',
      description: 'Centralised identity and access management broker',
      type: AssetType.WEB_APPLICATION,
      environment: Environment.PRODUCTION,
      department: 'Security',
      classification: 'Internal',
      criticality: 'Critical',
      ownerId: meera.id,
      ownerEmail: 'meera.krishnan@msil.in',
      internetAccessible: false,
      piiData: false,
      biaApp: true,
      prodUrl: 'auth.msil.internal',
      preprodUrl: 'uat-auth.msil.internal',
      devUrl: 'dev-auth.msil.internal',

    },
    create: {
      appId: 'APP-0007',
      name: 'auth-service',
      description: 'Centralised identity and access management broker',
      type: AssetType.WEB_APPLICATION,
      environment: Environment.PRODUCTION,
      department: 'Security',
      classification: 'Internal',
      criticality: 'Critical',
      ownerId: meera.id,
      ownerEmail: 'meera.krishnan@msil.in',
      internetAccessible: false,
      piiData: false,
      biaApp: true,
      prodUrl: 'auth.msil.internal',
      preprodUrl: 'uat-auth.msil.internal',
      devUrl: 'dev-auth.msil.internal',

    },
  });

  apps['data-warehouse-v1'] = await prisma.application.upsert({
    where: { appId: 'APP-0028' },
    update: {
      name: 'data-warehouse-v1',
      description: 'Analytics data warehouse — BI reporting and dashboards',
      type: AssetType.WEB_APPLICATION,
      environment: Environment.PRODUCTION,
      department: 'Analytics',
      classification: 'Internal',
      criticality: 'Critical',
      ownerId: priyaV.id,
      ownerEmail: 'priya.verma@msil.in',
      internetAccessible: false,
      piiData: true,
      biaApp: false,
      prodUrl: 'dw.analytics.msil.in',
      preprodUrl: 'uat-dw.msil.in',

    },
    create: {
      appId: 'APP-0028',
      name: 'data-warehouse-v1',
      description: 'Analytics data warehouse — BI reporting and dashboards',
      type: AssetType.WEB_APPLICATION,
      environment: Environment.PRODUCTION,
      department: 'Analytics',
      classification: 'Internal',
      criticality: 'Critical',
      ownerId: priyaV.id,
      ownerEmail: 'priya.verma@msil.in',
      internetAccessible: false,
      piiData: true,
      biaApp: false,
      prodUrl: 'dw.analytics.msil.in',
      preprodUrl: 'uat-dw.msil.in',

    },
  });

  apps['vendor-portal'] = await prisma.application.upsert({
    where: { appId: 'APP-0053' },
    update: {
      name: 'vendor-portal',
      description: 'Supplier and third-party vendor collaboration portal',
      type: AssetType.WEB_APPLICATION,
      environment: Environment.PRODUCTION,
      department: 'Risk & Compliance',
      classification: 'Internet Facing',
      criticality: 'Non-Critical',
      ownerId: jai.id,
      ownerEmail: 'jai.tiwari@msil.in',
      internetAccessible: true,
      piiData: true,
      biaApp: false,
      prodUrl: 'vendors.msil.com',
      preprodUrl: 'uat-vendors.msil.com',

    },
    create: {
      appId: 'APP-0053',
      name: 'vendor-portal',
      description: 'Supplier and third-party vendor collaboration portal',
      type: AssetType.WEB_APPLICATION,
      environment: Environment.PRODUCTION,
      department: 'Risk & Compliance',
      classification: 'Internet Facing',
      criticality: 'Non-Critical',
      ownerId: jai.id,
      ownerEmail: 'jai.tiwari@msil.in',
      internetAccessible: true,
      piiData: true,
      biaApp: false,
      prodUrl: 'vendors.msil.com',
      preprodUrl: 'uat-vendors.msil.com',

    },
  });

  apps['billing-portal'] = await prisma.application.upsert({
    where: { appId: 'APP-0019' },
    update: {
      name: 'billing-portal',
      description: 'Customer billing, invoicing and payment status portal',
      type: AssetType.WEB_APPLICATION,
      environment: Environment.PRODUCTION,
      department: 'Finance IT',
      classification: 'Internet Facing',
      criticality: 'Non-Critical',
      ownerId: aanya.id,
      ownerEmail: 'aanya.sharma@msil.in',
      internetAccessible: true,
      piiData: true,
      biaApp: false,
      prodUrl: 'billing.msil.com',
      preprodUrl: 'uat-billing.msil.com',

    },
    create: {
      appId: 'APP-0019',
      name: 'billing-portal',
      description: 'Customer billing, invoicing and payment status portal',
      type: AssetType.WEB_APPLICATION,
      environment: Environment.PRODUCTION,
      department: 'Finance IT',
      classification: 'Internet Facing',
      criticality: 'Non-Critical',
      ownerId: aanya.id,
      ownerEmail: 'aanya.sharma@msil.in',
      internetAccessible: true,
      piiData: true,
      biaApp: false,
      prodUrl: 'billing.msil.com',
      preprodUrl: 'uat-billing.msil.com',

    },
  });

  apps['internal-wiki'] = await prisma.application.upsert({
    where: { appId: 'APP-0061' },
    update: {
      name: 'internal-wiki',
      description: 'Internal knowledge base and documentation platform',
      type: AssetType.WEB_APPLICATION,
      environment: Environment.PRODUCTION,
      department: 'IT Ops',
      classification: 'Internal',
      criticality: 'Non-Critical',
      ownerId: suresh.id,
      ownerEmail: 'suresh.nair@msil.in',
      internetAccessible: false,
      piiData: false,
      biaApp: false,
      prodUrl: 'wiki.msil.internal',

    },
    create: {
      appId: 'APP-0061',
      name: 'internal-wiki',
      description: 'Internal knowledge base and documentation platform',
      type: AssetType.WEB_APPLICATION,
      environment: Environment.PRODUCTION,
      department: 'IT Ops',
      classification: 'Internal',
      criticality: 'Non-Critical',
      ownerId: suresh.id,
      ownerEmail: 'suresh.nair@msil.in',
      internetAccessible: false,
      piiData: false,
      biaApp: false,
      prodUrl: 'wiki.msil.internal',

    },
  });

  console.log(`✅ Applications (${Object.keys(apps).length})`);

  // ===========================================================================
  // INFRASTRUCTURE ASSETS — infra.ts: mockInfraSummaries / mockInfraDetails /
  // mockInfraInventory. 6 unique assets (5 with full detail + erp-app-prod-01
  // from the inventory list only).
  // ===========================================================================

  const infra: Record<string, InfrastructureAsset> = {};

  infra['edge-router-fw'] = await prisma.infrastructureAsset.upsert({
    where: { serverId: 'SRV-0001' },
    update: {},
    create: {
      serverId: 'SRV-0001',
      serverName: 'edge-router-fw',
      hostname: 'fw-edge-01.msil.internal',
      ip: '10.0.0.1',
      publicIp: true,
      type: InfraType.FIREWALL,
      environment: Environment.PRODUCTION,
      location: 'On-Premise (Gurgaon DC)',
      os: 'FortiOS 7.4.3',
      role: 'Edge firewall and perimeter router — controls all internet-facing traffic for MSIL',
      primaryApp: '—',
      criticality: 'Critical',
      assetOwnerId: vijay.id,
      assetOwnerEmail: 'vijay.mehta@msil.in',
      appOwnerEmail: '—',
      biaApp: false,

    },
  });

  infra['payments-db-cluster'] = await prisma.infrastructureAsset.upsert({
    where: { serverId: 'SRV-0024' },
    update: {},
    create: {
      serverId: 'SRV-0024',
      serverName: 'payments-db-cluster',
      hostname: 'paydb-01.msil.internal',
      ip: '10.4.1.50',
      publicIp: false,
      type: InfraType.DATABASE_SERVER,
      environment: Environment.PRODUCTION,
      location: 'AWS ap-south-1',
      os: 'RHEL 9.3',
      role: 'Primary payments database cluster — handles all transaction and reconciliation data',
      primaryApp: 'payments-api',
      criticality: 'Critical',
      assetOwnerId: aanya.id,
      assetOwnerEmail: 'aanya.sharma@msil.in',
      appOwnerEmail: 'aanya.sharma@msil.in',
      biaApp: true,

    },
  });

  infra['ci-runner-pool'] = await prisma.infrastructureAsset.upsert({
    where: { serverId: 'SRV-0041' },
    update: {},
    create: {
      serverId: 'SRV-0041',
      serverName: 'ci-runner-pool',
      hostname: 'ci-runner.msil.internal',
      ip: '10.5.0.10',
      publicIp: false,
      type: InfraType.VIRTUAL_MACHINE,
      environment: Environment.DEVELOPMENT,
      location: 'Azure East (East US)',
      os: 'Ubuntu 20.04 LTS',
      role: 'Build and test runner pool — GitHub Actions self-hosted runners for all MSIL engineering teams',
      primaryApp: 'CI/CD Runners',
      criticality: 'High',
      assetOwnerId: kiranDev.id,
      assetOwnerEmail: 'kiran.dev@msil.in',
      appOwnerEmail: '—',
      biaApp: false,

    },
  });

  infra['k8s-prod-eu'] = await prisma.infrastructureAsset.upsert({
    where: { serverId: 'SRV-0057' },
    update: {},
    create: {
      serverId: 'SRV-0057',
      serverName: 'k8s-prod-eu',
      hostname: 'k8s-eu.msil.internal',
      ip: '10.6.0.1',
      publicIp: false,
      type: InfraType.CONTAINER_CLUSTER,
      environment: Environment.PRODUCTION,
      location: 'AWS eu-west-1',
      os: 'Ubuntu 22.04 LTS',
      role: 'Production Kubernetes cluster (EU) — hosts auth-service and billing-portal workloads',
      primaryApp: 'auth-service, billing-portal',
      criticality: 'High',
      assetOwnerId: rohit.id,
      assetOwnerEmail: 'rohit.sharma@msil.in',
      appOwnerEmail: 'meera.krishnan@msil.in',
      biaApp: false,

    },
  });

  infra['erp-db-prod-01'] = await prisma.infrastructureAsset.upsert({
    where: { serverId: 'SRV-0018' },
    update: {},
    create: {
      serverId: 'SRV-0018',
      serverName: 'erp-db-prod-01',
      hostname: 'erp-db-01.msil.internal',
      ip: '10.4.2.18',
      publicIp: false,
      type: InfraType.DATABASE_SERVER,
      environment: Environment.PRODUCTION,
      location: 'AWS ap-south-1',
      os: 'Ubuntu 22.04 LTS',
      role: 'Primary database for legacy ERP — stores production operations data',
      primaryApp: 'legacy-erp',
      criticality: 'Critical',
      assetOwnerId: vijay.id,
      assetOwnerEmail: 'vijay.mehta@msil.in',
      appOwnerEmail: 'rohit.sharma@msil.in',
      biaApp: true,

    },
  });

  infra['erp-app-prod-01'] = await prisma.infrastructureAsset.upsert({
    where: { serverId: 'SRV-0033' },
    update: {},
    create: {
      serverId: 'SRV-0033',
      serverName: 'erp-app-prod-01',
      hostname: 'erp-app-01.msil.internal',
      ip: '10.4.2.19',
      publicIp: false,
      type: InfraType.PHYSICAL_SERVER,
      environment: Environment.PRODUCTION,
      location: 'On-Premise',
      os: 'Windows Server 2022',
      role: 'ERP application server',
      primaryApp: 'legacy-erp',
      criticality: 'Critical',
      assetOwnerId: vijay.id,
      assetOwnerEmail: 'vijay.mehta@msil.in',
      appOwnerEmail: 'rohit.sharma@msil.in',
      biaApp: true,

    },
  });

  console.log(`✅ Infrastructure Assets (${Object.keys(infra).length})`);

  // ===========================================================================
  // APP <-> INFRASTRUCTURE JUNCTIONS (derived from primaryApp / appOwnerEmail)
  // ===========================================================================

  const appInfraLinks: Array<[string, string]> = [
    ['legacy-erp', 'erp-db-prod-01'],
    ['legacy-erp', 'erp-app-prod-01'],
    ['payments-api', 'payments-db-cluster'],
    ['auth-service', 'k8s-prod-eu'],
    ['billing-portal', 'k8s-prod-eu'],
  ];
  for (const [appKey, infraKey] of appInfraLinks) {
    await prisma.appInfrastructureAsset.upsert({
      where: {
        applicationId_infrastructureAssetId: {
          applicationId: apps[appKey].id,
          infrastructureAssetId: infra[infraKey].id,
        },
      },
      update: {},
      create: { applicationId: apps[appKey].id, infrastructureAssetId: infra[infraKey].id },
    });
  }
  console.log('✅ App ↔ Infrastructure links');

  // ===========================================================================
  // CLOUD ACCOUNTS — cloud.ts: mockCloudAccounts (4 accounts)
  // ===========================================================================

  const ca1 = await prisma.cloudAccount.upsert({
    where: { accountId: 'CA-001' },
    update: {},
    create: { accountId: 'CA-001', extId: '123456789012', provider: CloudProvider.AWS, environment: Environment.PRODUCTION, label: 'AWS Production — legacy-erp / payments-api' },
  });
  const ca2 = await prisma.cloudAccount.upsert({
    where: { accountId: 'CA-002' },
    update: {},
    create: { accountId: 'CA-002', extId: '987654321098', provider: CloudProvider.AWS, environment: Environment.PRODUCTION, label: 'AWS Production — auth-service / billing-portal' },
  });
  const ca3 = await prisma.cloudAccount.upsert({
    where: { accountId: 'CA-003' },
    update: {},
    create: { accountId: 'CA-003', extId: '456789012345', provider: CloudProvider.AZURE, environment: Environment.DEVELOPMENT, label: 'Azure Non-Production — CI/CD' },
  });
  const ca4 = await prisma.cloudAccount.upsert({
    where: { accountId: 'CA-004' },
    update: {},
    create: { accountId: 'CA-004', extId: '234567890123', provider: CloudProvider.AWS, environment: Environment.DEVELOPMENT, label: 'AWS Development — legacy-erp(dev) / payments-api(dev)' },
  });
  console.log('✅ Cloud Accounts (4)');

  // ===========================================================================
  // CLOUD RESOURCES — cloud.ts: mockCloudResources (10 resources)
  // ===========================================================================

  const cr: Record<string, Awaited<ReturnType<typeof prisma.cloudResource.upsert>>> = {};

  cr['CR-001'] = await prisma.cloudResource.upsert({
    where: { resourceId: 'CR-001' },
    update: {},
    create: {
      resourceId: 'CR-001', resourceExtId: 'i-0a1b2c3d4e5f6a7b', resourceName: 'erp-db-prod-01',
      type: CloudResourceType.COMPUTE, technologyName: 'Amazon EC2', stackLayer: 'Infrastructure',
      cloudProvider: CloudProvider.AWS, cloudAccountId: ca1.id, status: 'Running', region: 'ap-south-1',
      environment: Environment.PRODUCTION, infraAssetId: infra['erp-db-prod-01'].id, firstSeen: d('2022-01-14 09:23:11'),
    },
  });
  cr['CR-002'] = await prisma.cloudResource.upsert({
    where: { resourceId: 'CR-002' },
    update: {},
    create: {
      resourceId: 'CR-002', resourceExtId: 'db-ms1l-pay-prod', resourceName: 'payments-db-cluster',
      type: CloudResourceType.DATABASE, technologyName: 'Amazon RDS', stackLayer: 'Data',
      cloudProvider: CloudProvider.AWS, cloudAccountId: ca1.id, status: 'Available', region: 'ap-south-1',
      environment: Environment.PRODUCTION, infraAssetId: infra['payments-db-cluster'].id, firstSeen: d('2023-05-20 11:44:30'),
    },
  });
  cr['CR-003'] = await prisma.cloudResource.upsert({
    where: { resourceId: 'CR-003' },
    update: {},
    create: {
      resourceId: 'CR-003', resourceExtId: 'cluster-msil-eu-k8s', resourceName: 'k8s-prod-eu',
      type: CloudResourceType.CONTAINER, technologyName: 'Amazon EKS', stackLayer: 'Platform',
      cloudProvider: CloudProvider.AWS, cloudAccountId: ca2.id, status: 'Active', region: 'eu-west-1',
      environment: Environment.PRODUCTION, infraAssetId: infra['k8s-prod-eu'].id, firstSeen: d('2023-10-08 07:02:55'),
    },
  });
  cr['CR-004'] = await prisma.cloudResource.upsert({
    where: { resourceId: 'CR-004' },
    update: {},
    create: {
      resourceId: 'CR-004', resourceExtId: 'vm-msil-ci-runner-01', resourceName: 'ci-runner-pool',
      type: CloudResourceType.COMPUTE, technologyName: 'Azure VM', stackLayer: 'Infrastructure',
      cloudProvider: CloudProvider.AZURE, cloudAccountId: ca3.id, status: 'Running', region: 'East US',
      environment: Environment.DEVELOPMENT, infraAssetId: infra['ci-runner-pool'].id, firstSeen: d('2023-03-15 13:11:00'),
    },
  });
  cr['CR-005'] = await prisma.cloudResource.upsert({
    where: { resourceId: 'CR-005' },
    update: {},
    create: {
      resourceId: 'CR-005', resourceExtId: 'apigw-msil-pay-prod', resourceName: 'payments-api-gateway',
      type: CloudResourceType.GATEWAY, technologyName: 'Amazon API Gateway', stackLayer: 'Application',
      cloudProvider: CloudProvider.AWS, cloudAccountId: ca1.id, status: 'Active', region: 'ap-south-1',
      environment: Environment.PRODUCTION, firstSeen: d('2023-05-20 12:00:00'),
    },
  });
  cr['CR-006'] = await prisma.cloudResource.upsert({
    where: { resourceId: 'CR-006' },
    update: {},
    create: {
      resourceId: 'CR-006', resourceExtId: 's3-msil-erp-bkp-2022', resourceName: 'erp-s3-backup',
      type: CloudResourceType.STORAGE, technologyName: 'Amazon S3', stackLayer: 'Data',
      cloudProvider: CloudProvider.AWS, cloudAccountId: ca1.id, status: 'Active', region: 'ap-south-1',
      environment: Environment.PRODUCTION, firstSeen: d('2022-03-08 16:45:22'),
    },
  });
  cr['CR-007'] = await prisma.cloudResource.upsert({
    where: { resourceId: 'CR-007' },
    update: {},
    create: {
      resourceId: 'CR-007', resourceExtId: 'alb-msil-auth-svc-eu', resourceName: 'auth-service-alb',
      type: CloudResourceType.NETWORK, technologyName: 'AWS ALB', stackLayer: 'Network',
      cloudProvider: CloudProvider.AWS, cloudAccountId: ca2.id, status: 'Active', region: 'eu-west-1',
      environment: Environment.PRODUCTION, firstSeen: d('2023-10-12 08:30:14'),
    },
  });
  cr['CR-008'] = await prisma.cloudResource.upsert({
    where: { resourceId: 'CR-008' },
    update: {},
    create: {
      resourceId: 'CR-008', resourceExtId: 'alb-msil-billing-eu', resourceName: 'billing-portal-alb',
      type: CloudResourceType.NETWORK, technologyName: 'AWS ALB', stackLayer: 'Network',
      cloudProvider: CloudProvider.AWS, cloudAccountId: ca2.id, status: 'Active', region: 'eu-west-1',
      environment: Environment.PRODUCTION, firstSeen: d('2023-11-01 10:17:44'),
    },
  });
  cr['CR-009'] = await prisma.cloudResource.upsert({
    where: { resourceId: 'CR-009' },
    update: {},
    create: {
      resourceId: 'CR-009', resourceExtId: 'waf-msil-prod-webacl', resourceName: 'msil-prod-waf',
      type: CloudResourceType.SECURITY, technologyName: 'AWS WAF', stackLayer: 'Security',
      cloudProvider: CloudProvider.AWS, cloudAccountId: ca1.id, status: 'Active', region: 'ap-south-1',
      environment: Environment.PRODUCTION, firstSeen: d('2023-06-01 09:00:00'),
    },
  });
  cr['CR-010'] = await prisma.cloudResource.upsert({
    where: { resourceId: 'CR-010' },
    update: {},
    create: {
      resourceId: 'CR-010', resourceExtId: 'lambda-msil-billing', resourceName: 'billing-invoice-lambda',
      type: CloudResourceType.SERVERLESS, technologyName: 'AWS Lambda', stackLayer: 'Application',
      cloudProvider: CloudProvider.AWS, cloudAccountId: ca2.id, status: 'Active', region: 'eu-west-1',
      environment: Environment.PRODUCTION, firstSeen: d('2023-12-10 14:22:37'),
    },
  });

  console.log(`✅ Cloud Resources (${Object.keys(cr).length})`);

  // App <-> Cloud Resource junctions, derived from CloudAccount.apps[] groupings
  // in cloud.ts plus resource-name correlation to applications.
  const appCloudLinks: Array<[string, string]> = [
    ['legacy-erp', 'CR-001'],
    ['legacy-erp', 'CR-006'],
    ['legacy-erp', 'CR-009'],
    ['payments-api', 'CR-002'],
    ['payments-api', 'CR-005'],
    ['payments-api', 'CR-009'],
    ['auth-service', 'CR-007'],
    ['auth-service', 'CR-003'],
    ['billing-portal', 'CR-008'],
    ['billing-portal', 'CR-010'],
    ['billing-portal', 'CR-003'],
  ];
  for (const [appKey, crKey] of appCloudLinks) {
    await prisma.appCloudResource.upsert({
      where: { applicationId_cloudResourceId: { applicationId: apps[appKey].id, cloudResourceId: cr[crKey].id } },
      update: {},
      create: { applicationId: apps[appKey].id, cloudResourceId: cr[crKey].id },
    });
  }
  console.log('✅ App ↔ Cloud Resource links');

  // ===========================================================================
  // SECURITY REQUESTS
  // Built from requests.ts (unified ops table — authoritative for status/dates),
  // cross-referenced against vapt.ts, bb.ts, cs.ts, rt.ts, cvs.ts, and the VAPT
  // history rows embedded in apps.ts.
  // ===========================================================================

  const sr: Record<string, Awaited<ReturnType<typeof prisma.securityRequest.upsert>>> = {};

  // --- VAPT-2025-0042 — legacy-erp, SecureLayer7, full detail in vapt.ts -------
  sr['VAPT-2025-0042'] = await prisma.securityRequest.upsert({
    where: { reqId: 'VAPT-2025-0042' },
    update: {},
    create: {
      reqId: 'VAPT-2025-0042',
      source: RequestSource.VAPT,
      environment: Environment.PRODUCTION,
      status: RequestStatus.IN_PROGRESS,
      targetAppId: apps['legacy-erp'].id,
      partner: 'SecureLayer7',
      initiatedById: aanya.id,
      assignedToId: rohit.id,
      initiatedOn: d('Mar 12, 2026'),
      startedAt: d('Mar 01, 2026'),
      findingsSharedAt: d('Mar 14, 2026'),
      totalFindings: 5,
      openFindings: 4,
      critFindings: 3,
      highFindings: 2,
      slaCompliance: 42,
      assessmentMeta: {
        vaptType: 'PERIODIC',
        scope: 'Web Application',
        totalUserRoles: 5,
        plannedLiveDate: 'Apr 01, 2026',
        mvpReleaseDate: 'May 15, 2026',
        facing: 'Internet Facing',
        authMechanism: 'LDAP SSO + MFA via MS Authenticator. Bypass via shared test account.',
        accessibleWithoutVpn: false,
        hasApis: true,
        postmanCollection: 'erp-api-collection-v3.json (uploaded)',
        apiDocUrl: 'https://uat-erp.msil.internal/api/docs',
        apiAccessibleWithoutVpn: false,
        prodUrls: 'https://erp.msil.internal/',
        nonProdUrls: 'uat: https://uat-erp.msil.internal/',
        cloudDeployed: true,
        cloudDetails: 'Yes — AWS ap-south-1',
        wafInPlace: true,
        focusAreas: 'Authentication flows, admin panel privilege escalation, file upload endpoints, payment integration APIs.',
        specialInstructions: 'Avoid destructive payloads on the payroll export endpoint. Coordinate with Rohit Sharma for sensitive modules.',
      },
    },
  });

  // --- VAPT-2025-0039 — payments-api, Qualys (per apps.ts vaptHistory/requests.ts)
  sr['VAPT-2025-0039'] = await prisma.securityRequest.upsert({
    where: { reqId: 'VAPT-2025-0039' },
    update: {},
    create: {
      reqId: 'VAPT-2025-0039',
      source: RequestSource.VAPT,
      environment: Environment.PRE_PRODUCTION,
      status: RequestStatus.IN_PROGRESS,
      targetAppId: apps['payments-api'].id,
      partner: 'Qualys',
      initiatedById: aanya.id,
      assignedToId: aanya.id,
      initiatedOn: d('Apr 01, 2026'),
      startedAt: d('Feb 03, 2026'),
      findingsSharedAt: d('Feb 17, 2026'),
      totalFindings: 0,
      openFindings: 0,
      critFindings: 0,
      highFindings: 0,
      slaCompliance: 74,
      assessmentMeta: { vaptType: 'PRE_RELEASE' },
    },
  });

  // --- BB-2025-0019 — legacy-erp, BugCrowd --------------------------------------
  sr['BB-2025-0019'] = await prisma.securityRequest.upsert({
    where: { reqId: 'BB-2025-0019' },
    update: {},
    create: {
      reqId: 'BB-2025-0019',
      source: RequestSource.BUG_BOUNTY,
      environment: Environment.PRODUCTION,
      status: RequestStatus.OPEN,
      targetAppId: apps['legacy-erp'].id,
      partner: 'BugCrowd',
      initiatedById: rohit.id,
      initiatedOn: d('Mar 10, 2026'),
      totalFindings: 1,
      openFindings: 1,
      critFindings: 0,
      highFindings: 1,
      slaCompliance: 100,
      assessmentMeta: { programme: 'BugCrowd', engagementPeriod: '—' },
    },
  });

  // --- BB-2026-0001 — payments-api, HackerOne -----------------------------------
  sr['BB-2026-0001'] = await prisma.securityRequest.upsert({
    where: { reqId: 'BB-2026-0001' },
    update: {},
    create: {
      reqId: 'BB-2026-0001',
      source: RequestSource.BUG_BOUNTY,
      environment: Environment.PRE_PRODUCTION,
      status: RequestStatus.SUBMITTED,
      targetAppId: apps['payments-api'].id,
      partner: 'HackerOne',
      programmeUrl: null,
      initiatedById: aanya.id,
      initiatedOn: d('May 20, 2026'),
      startedAt: d('Jun 01, 2026'),
      totalFindings: 3,
      openFindings: 3,
      critFindings: 2,
      highFindings: 1,
      slaCompliance: 74,
      assessmentMeta: { programme: 'HackerOne', engagementPeriod: 'Jun 01, 2026 – Jun 30, 2026' },
    },
  });

  // --- RT-2025-0008 — payments-api, Cobalt.io -----------------------------------
  sr['RT-2025-0008'] = await prisma.securityRequest.upsert({
    where: { reqId: 'RT-2025-0008' },
    update: {},
    create: {
      reqId: 'RT-2025-0008',
      source: RequestSource.RED_TEAM,
      environment: Environment.PRODUCTION,
      status: RequestStatus.IN_PROGRESS,
      targetAppId: apps['payments-api'].id,
      partner: 'Cobalt.io',
      initiatedById: aanya.id,
      assignedToId: aanya.id,
      initiatedOn: d('Mar 28, 2026'),
      startedAt: d('Apr 01, 2026'),
      findingsSharedAt: d('Apr 15, 2026'),
      totalFindings: 3,
      openFindings: 3,
      critFindings: 2,
      highFindings: 1,
      slaCompliance: 100,
      assessmentMeta: { team: 'Cobalt.io', engagementPeriod: 'Apr 01–15, 2026' },
    },
  });

  // --- CS-2026-0001 — legacy-erp, CloudSek --------------------------------------
  sr['CS-2026-0001'] = await prisma.securityRequest.upsert({
    where: { reqId: 'CS-2026-0001' },
    update: {},
    create: {
      reqId: 'CS-2026-0001',
      source: RequestSource.CLOUDSEK,
      environment: Environment.PRODUCTION,
      status: RequestStatus.SUBMITTED,
      targetAppId: apps['legacy-erp'].id,
      initiatedById: aanya.id,
      initiatedOn: d('May 22, 2026'),
      totalFindings: 2,
      openFindings: 2,
      critFindings: 1,
      highFindings: 1,
      slaCompliance: 100,
      assessmentMeta: { integrationId: 'CS-2026-0001', scanProfile: 'External Threat Surface' },
    },
  });

  // --- VA-2026-0001 — edge-router-fw, auto-created from CVS findings -----------
  // No dedicated RequestSource exists for "Vulnerability Assessment"; per schema
  // comment, Qualys-style scanning is tracked under VAPT with partner = Qualys.
  sr['VA-2026-0001'] = await prisma.securityRequest.upsert({
    where: { reqId: 'VA-2026-0001' },
    update: {},
    create: {
      reqId: 'VA-2026-0001',
      source: RequestSource.VAPT,
      environment: Environment.PRODUCTION,
      status: RequestStatus.PATCHING,
      targetInfraId: infra['edge-router-fw'].id,
      partner: 'Qualys',
      initiatedById: null,
      assignedToId: vijay.id,
      initiatedOn: d('May 19, 2026'),
      startedAt: d('May 19, 2026'),
      totalFindings: 2,
      openFindings: 2,
      critFindings: 1,
      highFindings: 1,
      slaCompliance: 100,
      assessmentMeta: { vaptType: 'VULNERABILITY_ASSESSMENT', autoCreated: true, sourceScanner: 'VMP' },
    },
  });

  // --- Infra-targeted VAPT requests referenced only in infra.ts ----------------
  sr['VAPT-2025-0038'] = await prisma.securityRequest.upsert({
    where: { reqId: 'VAPT-2025-0038' },
    update: {},
    create: {
      reqId: 'VAPT-2025-0038',
      source: RequestSource.VAPT,
      environment: Environment.PRODUCTION,
      status: RequestStatus.OPEN,
      targetInfraId: infra['edge-router-fw'].id,
      partner: 'SecureLayer7',
      initiatedById: aanya.id,
      assignedToId: vijay.id,
      initiatedOn: d('Apr 20, 2026'),
      totalFindings: 2,
      openFindings: 2,
      critFindings: 2,
      highFindings: 0,
      slaCompliance: 80,
      assessmentMeta: { vaptType: 'PERIODIC', scope: 'Infrastructure — Edge Firewall + ERP DB' },
    },
  });

  sr['VAPT-2025-0041'] = await prisma.securityRequest.upsert({
    where: { reqId: 'VAPT-2025-0041' },
    update: {},
    create: {
      reqId: 'VAPT-2025-0041',
      source: RequestSource.VAPT,
      environment: Environment.DEVELOPMENT,
      status: RequestStatus.OPEN,
      targetInfraId: infra['ci-runner-pool'].id,
      partner: 'SecureLayer7',
      initiatedById: aanya.id,
      assignedToId: kiranDev.id,
      initiatedOn: d('Apr 22, 2026'),
      totalFindings: 2,
      openFindings: 2,
      critFindings: 1,
      highFindings: 1,
      slaCompliance: 87,
      assessmentMeta: { vaptType: 'PERIODIC', scope: 'Infrastructure — CI Runner Pool' },
    },
  });

  sr['VAPT-2025-0057'] = await prisma.securityRequest.upsert({
    where: { reqId: 'VAPT-2025-0057' },
    update: {},
    create: {
      reqId: 'VAPT-2025-0057',
      source: RequestSource.VAPT,
      environment: Environment.PRODUCTION,
      status: RequestStatus.OPEN,
      targetInfraId: infra['k8s-prod-eu'].id,
      partner: 'SecureLayer7',
      initiatedById: aanya.id,
      assignedToId: rohit.id,
      initiatedOn: d('Apr 24, 2026'),
      totalFindings: 2,
      openFindings: 2,
      critFindings: 1,
      highFindings: 1,
      slaCompliance: 81,
      assessmentMeta: { vaptType: 'PERIODIC', scope: 'Infrastructure — Kubernetes Cluster (EU)' },
    },
  });

  // --- Historical / closed VAPT requests from apps.ts VAPT history rows --------
  sr['VAPT-2024-0031'] = await prisma.securityRequest.upsert({
    where: { reqId: 'VAPT-2024-0031' },
    update: {},
    create: {
      reqId: 'VAPT-2024-0031', source: RequestSource.VAPT, environment: Environment.PRODUCTION, status: RequestStatus.CLOSED,
      targetAppId: apps['legacy-erp'].id, partner: 'SecureLayer7', initiatedById: rohit.id,
      initiatedOn: d('Sep 10, 2025'), findingsSharedAt: d('Sep 24, 2025'), closedAt: d('Sep 24, 2025'),
      totalFindings: 37, openFindings: 0, critFindings: 8, highFindings: 14, slaCompliance: 78,
      assessmentMeta: { vaptType: 'PERIODIC' },
    },
  });
  sr['VAPT-2023-0019'] = await prisma.securityRequest.upsert({
    where: { reqId: 'VAPT-2023-0019' },
    update: {},
    create: {
      reqId: 'VAPT-2023-0019', source: RequestSource.VAPT, environment: Environment.PRODUCTION, status: RequestStatus.CLOSED,
      targetAppId: apps['legacy-erp'].id, partner: 'Qualys', initiatedById: rohit.id,
      initiatedOn: d('Mar 05, 2025'), findingsSharedAt: d('Mar 18, 2025'), closedAt: d('Mar 18, 2025'),
      totalFindings: 29, openFindings: 0, critFindings: 4, highFindings: 11, slaCompliance: 91,
      assessmentMeta: { vaptType: 'PERIODIC' },
    },
  });
  sr['VAPT-2024-0028'] = await prisma.securityRequest.upsert({
    where: { reqId: 'VAPT-2024-0028' },
    update: {},
    create: {
      reqId: 'VAPT-2024-0028', source: RequestSource.VAPT, environment: Environment.PRODUCTION, status: RequestStatus.CLOSED,
      targetAppId: apps['payments-api'].id, partner: 'Qualys', initiatedById: aanya.id,
      initiatedOn: d('Aug 12, 2025'), findingsSharedAt: d('Aug 26, 2025'), closedAt: d('Aug 26, 2025'),
      totalFindings: 84, openFindings: 0, critFindings: 18, highFindings: 31, slaCompliance: 88,
      assessmentMeta: { vaptType: 'PERIODIC' },
    },
  });

  console.log(`✅ Security Requests (${Object.keys(sr).length})`);

  // ===========================================================================
  // VULNERABILITIES
  // From vapt.ts (5), vulnerabilities.ts/bb.ts (4 BB), vulnerabilities.ts/cs.ts (2),
  // vulnerabilities.ts/rt.ts (3), and the infra.ts-only infra VAPT findings.
  // ===========================================================================

  type VulnSeed = {
    vulnId: string;
    requestKey: string;
    source: RequestSource;
    environment: Environment;
    type: string;
    shortDesc: string;
    description?: string;
    severity: Severity;
    cvss?: number;
    cve?: string;
    affectedComponent?: string;
    references?: string[];
    status: VulnerabilityStatus;
    pendingWith?: string;
    assignedToId?: string;
    exploitAvail?: string;
    exploitConf?: string;
    poc?: string;
    remediation?: string;
    impact?: string;
    reportedBy?: string;
    reportedOn?: Date;
    slaDueDate?: Date;
    closedAt?: Date;
  };

  const vulnSeeds: VulnSeed[] = [
    // --- VAPT-2025-0042 (legacy-erp) — from vapt.ts ---------------------------
    {
      vulnId: 'VAPT-2025-0042-001', requestKey: 'VAPT-2025-0042', source: RequestSource.VAPT, environment: Environment.PRODUCTION,
      type: 'SQL Injection', shortDesc: 'Unsanitized input in /api/reports endpoint',
      description: 'The /api/reports endpoint accepts user-supplied input without sanitization, allowing an attacker to inject arbitrary SQL commands. This vulnerability enables full database read/write access.',
      severity: Severity.CRITICAL, cvss: 9.8, cve: 'CVE-2025-1042', affectedComponent: '/api/reports',
      references: ['CVE-2025-1042', 'OWASP A03:2021 — Injection', 'CWE-89'],
      status: VulnerabilityStatus.OPEN, pendingWith: 'Rohit Sharma', assignedToId: rohit.id,
      exploitAvail: 'Yes — Metasploit module', exploitConf: 'Confirmed',
      poc: 'GET /api/reports?id=1 OR 1=1-- returns all records from the reports table.',
      remediation: 'Use parameterized queries or prepared statements. Apply input validation. Deploy a WAF rule for SQLi patterns.',
      impact: 'Complete compromise of the database layer. An attacker can exfiltrate sensitive data including employee records, payroll data, and financial transactions.',
      reportedBy: 'SecureLayer7', reportedOn: d('Mar 14, 2026'), slaDueDate: d('May 03, 2026'),
    },
    {
      vulnId: 'VAPT-2025-0042-002', requestKey: 'VAPT-2025-0042', source: RequestSource.VAPT, environment: Environment.PRODUCTION,
      type: 'IDOR', shortDesc: 'No auth check on /user/[id]',
      description: 'The /user/[id] endpoint does not verify that the authenticated user has permission to access the requested resource. Any authenticated user can retrieve any user profile.',
      severity: Severity.CRITICAL, cvss: 9.1, affectedComponent: '/user/[id]',
      references: ['OWASP A01:2021 — Broken Access Control', 'CWE-639'],
      status: VulnerabilityStatus.OPEN, pendingWith: 'Rohit Sharma', assignedToId: rohit.id,
      poc: 'GET /user/1042 with any valid session token returns user 1042 profile regardless of ownership.',
      remediation: 'Implement object-level authorization checks. Verify the requesting user owns or has explicit access to the requested resource.',
      impact: 'Horizontal privilege escalation. Attackers can access PII, contact details, and role information for any user in the system.',
      reportedBy: 'SecureLayer7', reportedOn: d('Mar 14, 2026'), slaDueDate: d('May 03, 2026'),
    },
    {
      vulnId: 'VAPT-2025-0042-003', requestKey: 'VAPT-2025-0042', source: RequestSource.VAPT, environment: Environment.PRODUCTION,
      type: 'XSS', shortDesc: 'Reflected XSS via search parameter',
      description: "The search parameter q is reflected back in the page response without HTML encoding. Malicious script can be injected and executed in the victim's browser.",
      severity: Severity.HIGH, cvss: 7.4, affectedComponent: '/search?q=',
      references: ['OWASP A03:2021 — Injection', 'CWE-79', 'OWASP XSS Prevention Cheat Sheet'],
      status: VulnerabilityStatus.OPEN, pendingWith: 'Rohit Sharma', assignedToId: rohit.id,
      poc: 'GET /search?q=<script>alert(document.cookie)</script> — alert fires with session cookie value.',
      remediation: 'HTML-encode all user-supplied output. Implement a Content Security Policy (CSP). Use context-aware output encoding.',
      impact: 'Session hijacking, credential theft, defacement. Can be used to steal cookies or redirect users to phishing pages.',
      reportedBy: 'SecureLayer7', reportedOn: d('Mar 14, 2026'), slaDueDate: d('May 11, 2026'),
    },
    {
      vulnId: 'VAPT-2025-0042-004', requestKey: 'VAPT-2025-0042', source: RequestSource.VAPT, environment: Environment.PRODUCTION,
      type: 'Outdated TLS', shortDesc: 'TLS 1.0/1.1 enabled on API Gateway',
      description: 'The API Gateway nginx configuration allows TLS 1.0 and 1.1 in addition to TLS 1.2/1.3. These older protocol versions have known vulnerabilities (POODLE, BEAST).',
      severity: Severity.HIGH, cvss: 6.8, affectedComponent: 'nginx.conf',
      references: ['CVE-2014-3566 (POODLE)', 'NIST SP 800-52 Rev 2', 'CWE-326'],
      status: VulnerabilityStatus.OPEN, pendingWith: 'Rohit Sharma', assignedToId: rohit.id,
      poc: 'openssl s_client -connect api.msil.internal:443 -tls1 — connection established, TLS 1.0 accepted.',
      remediation: 'Disable TLS 1.0 and 1.1 in nginx.conf. Set ssl_protocols to TLSv1.2 TLSv1.3 only.',
      impact: 'Downgrade attacks enabling interception of encrypted traffic. Client connections may be exploited using known TLS vulnerabilities.',
      reportedBy: 'SecureLayer7', reportedOn: d('Mar 14, 2026'), slaDueDate: d('May 18, 2026'),
    },
    {
      vulnId: 'VAPT-2025-0042-005', requestKey: 'VAPT-2025-0042', source: RequestSource.VAPT, environment: Environment.PRODUCTION,
      type: 'Broken Access Control', shortDesc: 'Unauthenticated access to /admin panel',
      description: 'The /admin route was accessible without authentication in non-production environments. The middleware guard was not applied to this route group.',
      severity: Severity.CRITICAL, cvss: 9.4, affectedComponent: '/admin',
      references: ['OWASP A01:2021 — Broken Access Control', 'CWE-306'],
      status: VulnerabilityStatus.CLOSED, pendingWith: '—', assignedToId: rohit.id,
      poc: 'GET /admin — returns admin dashboard HTML with 200 OK. No auth cookie required.',
      remediation: 'Applied route-level auth middleware to the /admin route group. Verified fix in UAT. Closed after revalidation.',
      impact: 'Full administrative access including user management, configuration changes, and data exports without credentials.',
      reportedBy: 'SecureLayer7', reportedOn: d('Mar 14, 2026'), slaDueDate: d('Apr 28, 2026'), closedAt: d('Apr 28, 2026'),
    },

    // --- BB-2025-0019 (legacy-erp) ---------------------------------------------
    {
      vulnId: 'BB-2025-0019-001', requestKey: 'BB-2025-0019', source: RequestSource.BUG_BOUNTY, environment: Environment.PRODUCTION,
      type: 'Reflected XSS', shortDesc: 'Unsanitized input in search param',
      description: "The search parameter on the application's search page reflects user input directly into the HTML response without encoding. An attacker can craft a URL containing a script tag that executes in the victim's browser.",
      severity: Severity.HIGH, cvss: 7.4, affectedComponent: '/search?q= parameter',
      references: ['OWASP-A03:2021', 'CWE-79', 'CVE-2025-1182'],
      status: VulnerabilityStatus.OPEN, pendingWith: 'Frontend Dev',
      exploitAvail: 'Yes — PoC on GitHub', exploitConf: 'High',
      poc: 'https://legacy-erp.msil.internal/search?q=<script>alert(document.cookie)</script>',
      remediation: 'Apply output encoding on all reflected user input. Use Content-Security-Policy header. Validate input server-side.',
      impact: 'Session hijacking, credential theft, defacement. Affects all users who click a crafted link.',
      reportedBy: 'ext-researcher-4821', reportedOn: d('Mar 10, 2026'), slaDueDate: d('May 11, 2026'),
    },

    // --- BB-2026-0001 (payments-api) --------------------------------------------
    {
      vulnId: 'BB-2026-0001-001', requestKey: 'BB-2026-0001', source: RequestSource.BUG_BOUNTY, environment: Environment.PRE_PRODUCTION,
      type: 'Stored XSS', shortDesc: 'Stored XSS in payment description field',
      description: 'Malicious scripts stored in the payment description field execute for every user who views the transaction history page.',
      severity: Severity.HIGH, cvss: 7.4, affectedComponent: 'Payment Description Field',
      references: ['OWASP Top 10 A03', 'CWE-79'],
      status: VulnerabilityStatus.OPEN, pendingWith: 'HackerOne',
      poc: 'Submit payment with description: <img src=x onerror=alert(document.domain)>',
      remediation: 'Sanitize all stored user input. Apply DOMPurify on render.',
      impact: 'Mass session hijacking. Affects all users viewing transaction history.',
      reportedBy: 'HackerOne Researcher', reportedOn: d('Jun 01, 2026'), slaDueDate: d('Jun 15, 2026'),
    },
    {
      vulnId: 'BB-2026-0001-002', requestKey: 'BB-2026-0001', source: RequestSource.BUG_BOUNTY, environment: Environment.PRE_PRODUCTION,
      type: 'IDOR', shortDesc: 'Insecure Direct Object Reference on /transaction/[id]',
      description: 'The transaction detail endpoint does not verify that the authenticated user owns the transaction being requested. Any authenticated user can access any transaction by ID.',
      severity: Severity.CRITICAL, cvss: 8.8, affectedComponent: '/transaction/[id] endpoint',
      references: ['OWASP Top 10 A01', 'CWE-639'],
      status: VulnerabilityStatus.OPEN, pendingWith: 'HackerOne',
      poc: 'GET /api/transaction/12345 with any valid session token returns transaction regardless of ownership.',
      remediation: 'Implement ownership checks on all object access. Use indirect references.',
      impact: "Full exposure of other users' financial transaction data.",
      reportedBy: 'HackerOne Researcher', reportedOn: d('Jun 01, 2026'), slaDueDate: d('Jun 05, 2026'),
    },
    {
      vulnId: 'BB-2026-0001-003', requestKey: 'BB-2026-0001', source: RequestSource.BUG_BOUNTY, environment: Environment.PRE_PRODUCTION,
      type: 'SQL Injection', shortDesc: 'Blind SQL injection in payment filter endpoint',
      description: 'The payment filter endpoint is vulnerable to time-based blind SQL injection through the date_from parameter.',
      severity: Severity.CRITICAL, cvss: 9.1, affectedComponent: '/api/payments/filter endpoint',
      references: ['CWE-89', 'OWASP Top 10 A03', 'CVE-2025-2891'],
      status: VulnerabilityStatus.OPEN, pendingWith: 'HackerOne',
      poc: "date_from=2026-01-01' AND SLEEP(5)-- returns delayed response confirming injection.",
      remediation: 'Use parameterized queries. Apply WAF rules for SQLi patterns.',
      impact: 'Full database read access. Possible write/delete with elevated privileges.',
      reportedBy: 'HackerOne Researcher', reportedOn: d('Jun 01, 2026'), slaDueDate: d('Jun 01, 2026'),
    },

    // --- CS-2026-0001 (legacy-erp) -----------------------------------------------
    {
      vulnId: 'CS-2026-0001-001', requestKey: 'CS-2026-0001', source: RequestSource.CLOUDSEK, environment: Environment.PRODUCTION,
      type: 'SQL Injection', shortDesc: 'SQLi in /api/search endpoint — error-based',
      description: 'Unauthenticated SQL injection in the search endpoint allows database enumeration via error-based extraction.',
      severity: Severity.CRITICAL, cvss: 9.3, affectedComponent: '/api/search endpoint',
      references: ['CWE-89', 'CS-EXT-4821'],
      status: VulnerabilityStatus.OPEN, pendingWith: 'CloudSek',
      poc: "GET /api/search?q=' OR 1=1-- returns database error revealing schema.",
      remediation: 'Apply parameterized queries. Restrict error output in production.',
      impact: 'Full database read access without authentication.',
      reportedBy: 'CloudSek Platform', reportedOn: d('May 22, 2026'), slaDueDate: d('Jun 05, 2026'),
      externalIdValue: 'CS-EXT-4821',
    } as VulnSeed & { externalIdValue: string },
    {
      vulnId: 'CS-2026-0001-002', requestKey: 'CS-2026-0001', source: RequestSource.CLOUDSEK, environment: Environment.PRODUCTION,
      type: 'Credential Exposure', shortDesc: 'Hardcoded DB credentials in public JS bundle',
      description: 'Database connection credentials are hardcoded in the public JavaScript bundle, visible to any user via browser developer tools.',
      severity: Severity.HIGH, cvss: 7.6, affectedComponent: 'Login Page (JS bundle)',
      references: ['CWE-798', 'CS-EXT-4906'],
      status: VulnerabilityStatus.OPEN, pendingWith: 'CloudSek',
      poc: 'Inspect login page source via browser DevTools; search for hardcoded credential strings in the JS bundle.',
      remediation: 'Move credentials to server-side environment variables. Rotate exposed credentials immediately.',
      impact: 'Full database access for any user who inspects the page source.',
      reportedBy: 'CloudSek Platform', reportedOn: d('May 22, 2026'), slaDueDate: d('Jun 15, 2026'),
      externalIdValue: 'CS-EXT-4906',
    } as VulnSeed & { externalIdValue: string },

    // --- RT-2025-0008 (payments-api) — from vulnerabilities.ts -------------------
    {
      vulnId: 'RT-2025-0008-001', requestKey: 'RT-2025-0008', source: RequestSource.RED_TEAM, environment: Environment.PRODUCTION,
      type: 'Privilege Escalation', shortDesc: 'Misconfigured sudo allows root access',
      description: 'A misconfigured sudoers file on the production server allows any authenticated user to execute arbitrary commands as root without a password.',
      severity: Severity.CRITICAL, cvss: 9.6, affectedComponent: 'Production Server (sudo config)',
      references: ['CWE-269', 'MITRE T1548.003', 'Linux sudo CVE-2021-3156'],
      status: VulnerabilityStatus.PENDING_REVALIDATION, pendingWith: 'Aanya Sharma', assignedToId: aanya.id,
      exploitAvail: 'Yes — Actively exploited', exploitConf: 'Confirmed',
      poc: 'sudo -l reveals NOPASSWD entries. sudo /bin/bash provides immediate root shell.',
      remediation: 'Audit and restrict sudoers configuration. Remove NOPASSWD entries. Implement principle of least privilege for all service accounts.',
      impact: 'Full server compromise. Attacker gains root access to production infrastructure, enabling data exfiltration and lateral movement.',
      reportedBy: 'Cobalt.io Red Team', reportedOn: d('Mar 28, 2026'), slaDueDate: d('May 05, 2026'),
    },
    {
      vulnId: 'RT-2025-0008-002', requestKey: 'RT-2025-0008', source: RequestSource.RED_TEAM, environment: Environment.PRODUCTION,
      type: 'Unauth Admin Access', shortDesc: 'Exposed admin panel without authentication',
      description: 'The /admin panel is accessible from the internet without any authentication controls. Any user can reach administrative functions including user management and configuration.',
      severity: Severity.CRITICAL, cvss: 9.4, affectedComponent: '/admin endpoint',
      references: ['OWASP Top 10 A01:2021', 'CWE-306', 'MITRE T1190'],
      status: VulnerabilityStatus.OPEN, pendingWith: 'Aanya Sharma', assignedToId: aanya.id,
      poc: 'Navigate to https://payments-api.msil.internal/admin — full admin dashboard loads with no authentication prompt.',
      remediation: 'Restrict /admin to internal network only via firewall. Implement strong authentication (MFA required). Apply IP allowlisting.',
      impact: 'Full administrative takeover of the payments API. Unauthorized access to all user data and transaction records.',
      reportedBy: 'Cobalt.io Red Team', reportedOn: d('Mar 28, 2026'), slaDueDate: d('May 10, 2026'),
    },
    {
      vulnId: 'RT-2025-0008-003', requestKey: 'RT-2025-0008', source: RequestSource.RED_TEAM, environment: Environment.PRODUCTION,
      type: 'Credential Exposure', shortDesc: 'API keys hardcoded in front-end JS bundle',
      description: 'Live API keys for third-party payment processors are hardcoded in the minified JavaScript bundle served to all users. Keys are visible via browser developer tools.',
      severity: Severity.HIGH, cvss: 7.8, affectedComponent: 'Frontend JS bundle',
      references: ['CWE-798', 'OWASP Top 10 A02:2021', 'MITRE T1552'],
      status: VulnerabilityStatus.OPEN, pendingWith: 'Aanya Sharma', assignedToId: aanya.id,
      poc: 'Open browser DevTools → Sources → search for "sk_live_" in JS bundle. Keys found in payments.bundle.min.js.',
      remediation: 'Remove all hardcoded credentials from client-side code. Move to server-side environment variables. Rotate all exposed keys immediately.',
      impact: 'Unauthorized use of payment processor credentials. Financial fraud risk. Keys may be used to initiate fraudulent transactions.',
      reportedBy: 'Cobalt.io Red Team', reportedOn: d('Mar 28, 2026'), slaDueDate: d('May 12, 2026'),
    },

    // --- Infra-targeted VAPT findings (infra.ts) ----------------------------------
    {
      vulnId: 'VAPT-2025-0038-001', requestKey: 'VAPT-2025-0038', source: RequestSource.VAPT, environment: Environment.PRODUCTION,
      type: 'Default Credentials', shortDesc: 'Default SSH credentials present',
      description: 'Default SSH credentials remain active on the ERP database host, allowing unauthenticated access via factory-default login.',
      severity: Severity.CRITICAL, affectedComponent: 'Auth misconfiguration — erp-db-prod-01',
      status: VulnerabilityStatus.OPEN, pendingWith: 'Platform Team',
      remediation: 'Disable default SSH credentials and rotate to managed key-based authentication.',
      reportedBy: 'SecureLayer7', reportedOn: d('Apr 20, 2026'), slaDueDate: d('May 03, 2026'),
    },
    {
      vulnId: 'VAPT-2025-0038-002', requestKey: 'VAPT-2025-0038', source: RequestSource.VAPT, environment: Environment.PRODUCTION,
      type: 'Outdated Firmware', shortDesc: 'FortiOS firmware outdated — critical CVEs exposed',
      description: 'The edge firewall is running a FortiOS firmware version (7.4.0–7.4.2) with multiple disclosed critical CVEs.',
      severity: Severity.CRITICAL, affectedComponent: 'edge-router-fw firmware',
      status: VulnerabilityStatus.OPEN, pendingWith: 'Vijay Mehta', assignedToId: vijay.id,
      remediation: 'Upgrade FortiOS to the latest patched release and apply the relevant Fortinet security advisories.',
      reportedBy: 'SecureLayer7', reportedOn: d('Apr 20, 2026'), slaDueDate: d('May 10, 2026'),
    },
    {
      vulnId: 'VAPT-2025-0041-001', requestKey: 'VAPT-2025-0041', source: RequestSource.VAPT, environment: Environment.DEVELOPMENT,
      type: 'Container Misconfiguration', shortDesc: 'Docker daemon exposed without TLS',
      description: 'The Docker daemon on the CI runner pool is reachable without TLS client authentication, allowing unauthorized container control.',
      severity: Severity.CRITICAL, affectedComponent: 'ci-runner-pool Docker daemon',
      status: VulnerabilityStatus.OPEN, pendingWith: 'Kiran Dev', assignedToId: kiranDev.id,
      remediation: 'Enable TLS mutual authentication on the Docker daemon socket and restrict network exposure.',
      reportedBy: 'SecureLayer7', reportedOn: d('Apr 22, 2026'), slaDueDate: d('May 22, 2026'),
    },
    {
      vulnId: 'VAPT-2025-0041-002', requestKey: 'VAPT-2025-0041', source: RequestSource.VAPT, environment: Environment.DEVELOPMENT,
      type: 'Credential Exposure', shortDesc: 'Plaintext CI/CD tokens stored on disk',
      description: 'Self-hosted runner configuration stores CI/CD registration tokens in plaintext, readable by any local process.',
      severity: Severity.HIGH, affectedComponent: 'ci-runner-pool filesystem',
      status: VulnerabilityStatus.OPEN, pendingWith: 'Kiran Dev', assignedToId: kiranDev.id,
      remediation: 'Move tokens to a secrets manager and restrict filesystem permissions on the runner configuration directory.',
      reportedBy: 'SecureLayer7', reportedOn: d('Apr 22, 2026'), slaDueDate: d('May 30, 2026'),
    },
    {
      vulnId: 'VAPT-2025-0057-001', requestKey: 'VAPT-2025-0057', source: RequestSource.VAPT, environment: Environment.PRODUCTION,
      type: 'Exposed Management Interface', shortDesc: 'Kubernetes API server exposed to the internet',
      description: 'The k8s-prod-eu API server is reachable from outside the corporate network without IP allowlisting.',
      severity: Severity.CRITICAL, affectedComponent: 'k8s-prod-eu API server',
      status: VulnerabilityStatus.OPEN, pendingWith: 'Rohit Sharma', assignedToId: rohit.id,
      remediation: 'Restrict the Kubernetes API server to a private endpoint or allowlisted IP ranges, and enforce mutual TLS.',
      reportedBy: 'SecureLayer7', reportedOn: d('Apr 24, 2026'), slaDueDate: d('May 24, 2026'),
    },
    {
      vulnId: 'VAPT-2025-0057-002', requestKey: 'VAPT-2025-0057', source: RequestSource.VAPT, environment: Environment.PRODUCTION,
      type: 'Privileged Container', shortDesc: 'Privileged pods running without restriction',
      description: 'Multiple workloads on k8s-prod-eu run in privileged mode, granting broad host-level access if compromised.',
      severity: Severity.HIGH, affectedComponent: 'k8s-prod-eu workloads',
      status: VulnerabilityStatus.OPEN, pendingWith: 'Rohit Sharma', assignedToId: rohit.id,
      remediation: 'Enforce Kubernetes Pod Security Admission to disallow privileged containers across namespaces.',
      reportedBy: 'SecureLayer7', reportedOn: d('Apr 24, 2026'), slaDueDate: d('May 28, 2026'),
    },
  ];

  const createdVulnIds: Record<string, string> = {};
  for (const v of vulnSeeds) {
    const { requestKey, externalIdValue, ...rest } = v as VulnSeed & { externalIdValue?: string };
    const request = sr[requestKey];
    const created = await prisma.vulnerability.upsert({
      where: { vulnId: v.vulnId },
      update: {},
      create: {
        vulnId: rest.vulnId,
        requestId: request.id,
        source: rest.source,
        environment: rest.environment,
        type: rest.type,
        shortDesc: rest.shortDesc,
        description: rest.description,
        severity: rest.severity,
        cvss: rest.cvss,
        cve: rest.cve,
        affectedComponent: rest.affectedComponent,
        references: rest.references ?? [],
        status: rest.status,
        pendingWith: rest.pendingWith,
        assignedToId: rest.assignedToId,
        exploitAvail: rest.exploitAvail,
        exploitConf: rest.exploitConf,
        poc: rest.poc,
        remediation: rest.remediation,
        impact: rest.impact,
        reportedBy: rest.reportedBy,
        reportedOn: rest.reportedOn,
        slaDueDate: rest.slaDueDate,
        closedAt: rest.closedAt,
        externalId: externalIdValue ?? null,
      },
    });
    createdVulnIds[v.vulnId] = created.id;
  }
  console.log(`✅ Vulnerabilities (${vulnSeeds.length})`);

  // ===========================================================================
  // SCAN FINDINGS — cvs.ts: cvsFindings (8 raw Qualys/VMP scan findings)
  // Two are promoted to Vulnerability rows (VMP-2026-0001, VMP-2026-0002, both
  // under VA-2026-0001); the remaining six stay unpromoted, matching the mock
  // data where vaReqId is unset.
  // ===========================================================================

  type ScanFindingSeed = {
    findingId: string;
    type: string;
    shortDesc: string;
    description: string;
    poc: string;
    remediation: string;
    severity: Severity;
    cvss: number;
    cve: string;
    assetKey: string; // key into `infra`
    assetIp: string;
    assetOwner: string;
    assetEnv: Environment;
    vaReqId: string | null;
    status: string;
    timestamp: Date;
    promotedVulnId: string | null;
  };

  const scanFindingSeeds: ScanFindingSeed[] = [
    {
      findingId: 'VMP-2026-0001', type: 'Remote Code Execution', shortDesc: 'Unauthenticated RCE via FortiOS management interface',
      description: 'A stack-based buffer overflow in FortiOS SSL-VPN allows an unauthenticated remote attacker to execute arbitrary code or commands via specifically crafted HTTP requests to the management interface.',
      poc: 'Send crafted HTTP request to /remote/login with oversized user field. Observed reverse shell on attacker-controlled host.',
      remediation: 'Upgrade FortiOS to 7.4.4 or later. Disable management interface from public internet immediately. Apply Fortinet advisory FG-IR-24-015.',
      severity: Severity.CRITICAL, cvss: 9.8, cve: 'CVE-2024-21762', assetKey: 'edge-router-fw', assetIp: '10.0.0.1',
      assetOwner: 'Vijay Mehta', assetEnv: Environment.PRODUCTION, vaReqId: 'VA-2026-0001', status: 'Assigned',
      timestamp: d('May 19, 2026 04:00'), promotedVulnId: null,
    },
    {
      findingId: 'VMP-2026-0002', type: 'Default Credentials', shortDesc: 'Default admin credentials active on management interface',
      description: 'The FortiOS management interface is accessible with factory-default admin credentials (admin/blank). This allows complete administrative access without authentication.',
      poc: 'Navigate to https://10.0.0.1/admin — login with admin/(empty) succeeds.',
      remediation: 'Immediately change default admin password. Enable two-factor authentication on management interface. Restrict management access to trusted IPs only.',
      severity: Severity.HIGH, cvss: 7.9, cve: 'CWE-1392', assetKey: 'edge-router-fw', assetIp: '10.0.0.1',
      assetOwner: 'Vijay Mehta', assetEnv: Environment.PRODUCTION, vaReqId: 'VA-2026-0001', status: 'Assigned',
      timestamp: d('May 19, 2026 04:00'), promotedVulnId: null,
    },
    {
      findingId: 'VMP-2026-0003', type: 'SQL Injection', shortDesc: 'Blind SQL injection in /db/query endpoint',
      description: 'Time-based blind SQL injection found in the /db/query endpoint. Attacker can enumerate database schema, extract sensitive data including PII, and potentially achieve RCE via xp_cmdshell.',
      poc: 'GET /db/query?id=1 AND SLEEP(5)-- → response delayed by 5 seconds confirming injectable parameter.',
      remediation: 'Implement parameterized queries across all database interactions. Remove dynamic SQL construction. Apply input validation at controller layer. Consider using ORM.',
      severity: Severity.CRITICAL, cvss: 9.5, cve: 'CVE-2025-1042', assetKey: 'erp-db-prod-01', assetIp: '10.4.2.18',
      assetOwner: 'Rohit Sharma', assetEnv: Environment.PRODUCTION, vaReqId: null, status: 'In Progress',
      timestamp: d('May 19, 2026 04:00'), promotedVulnId: null,
    },
    {
      findingId: 'VMP-2026-0004', type: 'Outdated Component', shortDesc: 'PostgreSQL 14.2 — critical security patches missing',
      description: 'PostgreSQL version 14.2 is running on this server. Critical patches through 14.12 address privilege escalation and remote code execution vulnerabilities.',
      poc: 'Server banner reveals PostgreSQL 14.2. CVE-2024-7348 allows privilege escalation from postgres user to superuser.',
      remediation: 'Upgrade PostgreSQL to latest stable release (16.x). Schedule maintenance window for database upgrade. Test application compatibility before production deployment.',
      severity: Severity.HIGH, cvss: 8.1, cve: 'CVE-2024-7348', assetKey: 'erp-db-prod-01', assetIp: '10.4.2.18',
      assetOwner: 'Rohit Sharma', assetEnv: Environment.PRODUCTION, vaReqId: null, status: 'Unassigned',
      timestamp: d('May 19, 2026 04:00'), promotedVulnId: null,
    },
    {
      findingId: 'VMP-2026-0005', type: 'Unpatched OpenSSL', shortDesc: 'OpenSSL < 3.0.13 — CVE-2024-0727 active',
      description: 'Processing a maliciously formatted PKCS12 file may lead OpenSSL to crash, causing a denial of service. The affected version (OpenSSL 3.0.x < 3.0.13) can be triggered remotely via TLS handshake.',
      poc: 'Send crafted PKCS12 payload to SSL endpoint. Service crashes within 3 requests.',
      remediation: 'Upgrade OpenSSL to 3.0.13 or later. Restart affected services post-upgrade. Verify with: openssl version -a',
      severity: Severity.HIGH, cvss: 7.5, cve: 'CVE-2024-0727', assetKey: 'payments-db-cluster', assetIp: '10.4.1.50',
      assetOwner: 'Aanya Sharma', assetEnv: Environment.PRODUCTION, vaReqId: null, status: 'Assigned',
      timestamp: d('May 19, 2026 00:00'), promotedVulnId: null,
    },
    {
      findingId: 'VMP-2026-0006', type: 'Container Escape', shortDesc: 'Misconfigured seccomp allows kernel syscall abuse',
      description: 'A use-after-free vulnerability in the Linux kernel netfilter (nf_tables) subsystem allows container escape. Pods running without seccomp profiles can exploit this to gain root on the host node.',
      poc: 'Deploy exploit container — kernel panic sequence achieves host root within 45 seconds.',
      remediation: 'Apply Linux kernel patch >= 6.6.15. Enable restrictive seccomp profiles on all pods. Audit privileged containers. Enable Kubernetes PSA enforcement.',
      severity: Severity.CRITICAL, cvss: 9.3, cve: 'CVE-2024-1086', assetKey: 'k8s-prod-eu', assetIp: '10.6.0.1',
      assetOwner: 'Rohit Sharma', assetEnv: Environment.PRODUCTION, vaReqId: null, status: 'Unassigned',
      timestamp: d('May 19, 2026 04:00'), promotedVulnId: null,
    },
    {
      findingId: 'VMP-2026-0007', type: 'SSH Weak Key', shortDesc: 'RSA 1024-bit key in use — deprecated cipher',
      description: 'SSH server is using 1024-bit RSA host keys. Keys below 2048 bits are considered cryptographically weak and vulnerable to factorization attacks.',
      poc: 'ssh-keyscan reveals rsa-sha2-256 with 1024-bit modulus.',
      remediation: 'Regenerate SSH host keys using RSA 4096-bit or Ed25519. Update SSH configuration to disable weak ciphers. Restart SSH service.',
      severity: Severity.MEDIUM, cvss: 5.9, cve: 'CWE-326', assetKey: 'ci-runner-pool', assetIp: '10.5.0.10',
      assetOwner: 'Kiran Dev', assetEnv: Environment.PRE_PRODUCTION, vaReqId: null, status: 'Patched',
      timestamp: d('May 15, 2026 00:00'), promotedVulnId: null,
    },
    {
      findingId: 'VMP-2026-0008', type: 'SMB Relay Attack', shortDesc: 'SMBv1 enabled — susceptible to relay attacks',
      description: 'SMBv1 is enabled on this Windows Server 2022 system. SMBv1 is deprecated and susceptible to relay attacks (NTLM relay, EternalBlue). MS17-010 variant patterns observed.',
      poc: 'SMBv1 negotiation accepted on port 445. Relay attack captured Net-NTLMv1 hash in test environment.',
      remediation: 'Disable SMBv1 via PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false. Verify with Get-SmbServerConfiguration. Ensure SMBv3 signing is enabled.',
      severity: Severity.HIGH, cvss: 7.8, cve: 'CVE-2017-0144', assetKey: 'erp-app-prod-01', assetIp: '10.4.2.19',
      assetOwner: 'Vijay Mehta', assetEnv: Environment.PRODUCTION, vaReqId: null, status: 'Unassigned',
      timestamp: d('May 19, 2026 08:00'), promotedVulnId: null,
    },
  ];

  const scanFindings: Record<string, Awaited<ReturnType<typeof prisma.scanFinding.upsert>>> = {};
  for (const f of scanFindingSeeds) {
    scanFindings[f.findingId] = await prisma.scanFinding.upsert({
      where: { findingId: f.findingId },
      update: {},
      create: {
        findingId: f.findingId,
        type: f.type,
        shortDesc: f.shortDesc,
        description: f.description,
        poc: f.poc,
        remediation: f.remediation,
        severity: f.severity,
        cvss: f.cvss,
        cve: f.cve,
        assetId: infra[f.assetKey].id,
        assetName: infra[f.assetKey].serverName,
        assetIp: f.assetIp,
        assetOwner: f.assetOwner,
        assetEnv: f.assetEnv,
        vaReqId: f.vaReqId,
        status: f.status,
        timestamp: f.timestamp,
      },
    });
  }
  console.log(`✅ Scan Findings (${Object.keys(scanFindings).length})`);

  for (const f of scanFindingSeeds) {
    const isPatched = f.status === 'Patched' || f.status === 'Closed';
    const ownerId = f.assetOwner === 'Vijay Mehta' ? vijay.id :
                    f.assetOwner === 'Rohit Sharma' ? rohit.id :
                    f.assetOwner === 'Aanya Sharma' ? aanya.id :
                    f.assetOwner === 'Kiran Dev' ? kiranDev.id : null;

    const mapSeverity = (s: string): Severity => {
      const upper = s.toUpperCase();
      if (upper === 'CRITICAL') return Severity.CRITICAL;
      if (upper === 'HIGH') return Severity.HIGH;
      if (upper === 'MEDIUM') return Severity.MEDIUM;
      if (upper === 'LOW') return Severity.LOW;
      return Severity.INFORMATIONAL;
    };

    await prisma.continuousScanFinding.upsert({
      where: { id: f.findingId },
      update: {},
      create: {
        id: f.findingId,
        scannerName: 'VMP Scanner',
        assetId: infra[f.assetKey].id,
        assetName: infra[f.assetKey].serverName,
        vulnTitle: f.shortDesc,
        cve: f.cve,
        severity: mapSeverity(f.severity),
        cvss: f.cvss,
        status: isPatched ? 'PATCHED' : f.status === 'Unassigned' ? 'NEW' : 'IN_PROGRESS',
        assignedOwnerId: f.status === 'Unassigned' ? null : ownerId,
        firstSeenAt: new Date(f.timestamp.getTime() - 86400000),
        lastSeenAt: f.timestamp,
        slaDueAt: new Date(f.timestamp.getTime() + 86400000 * 30),
        patchedAt: isPatched ? f.timestamp : null,
        assignedAt: f.status !== 'Unassigned' ? f.timestamp : null,
        createdAt: f.timestamp,
      },
    });
  }
  console.log(`✅ Continuous Scan Findings (${scanFindingSeeds.length})`);

  // Promote VMP-2026-0001 and VMP-2026-0002 into Vulnerability rows under
  // VA-2026-0001, mirroring cvs.ts where both findings already carry
  // vaReqId: 'VA-2026-0001'.
  const promotedVulnSeeds: Array<{ vulnId: string; findingId: string; type: string; shortDesc: string; description: string; severity: Severity; cvss: number; cve: string; poc: string; remediation: string; status: VulnerabilityStatus; pendingWith: string; assignedToId: string; }> = [
    {
      vulnId: 'VMP-2026-0001', findingId: 'VMP-2026-0001', type: 'Remote Code Execution', shortDesc: 'Unauthenticated RCE via FortiOS management interface',
      description: 'A stack-based buffer overflow in FortiOS SSL-VPN allows an unauthenticated remote attacker to execute arbitrary code or commands via specifically crafted HTTP requests to the management interface.',
      severity: Severity.CRITICAL, cvss: 9.8, cve: 'CVE-2024-21762',
      poc: 'Send crafted HTTP request to /remote/login with oversized user field. Observed reverse shell on attacker-controlled host.',
      remediation: 'Upgrade FortiOS to 7.4.4 or later. Disable management interface from public internet immediately. Apply Fortinet advisory FG-IR-24-015.',
      status: VulnerabilityStatus.ASSIGNED, pendingWith: 'Vijay Mehta', assignedToId: vijay.id,
    },
    {
      vulnId: 'VMP-2026-0002', findingId: 'VMP-2026-0002', type: 'Default Credentials', shortDesc: 'Default admin credentials active on management interface',
      description: 'The FortiOS management interface is accessible with factory-default admin credentials (admin/blank). This allows complete administrative access without authentication.',
      severity: Severity.HIGH, cvss: 7.9, cve: 'CWE-1392',
      poc: 'Navigate to https://10.0.0.1/admin — login with admin/(empty) succeeds.',
      remediation: 'Immediately change default admin password. Enable two-factor authentication on management interface. Restrict management access to trusted IPs only.',
      status: VulnerabilityStatus.ASSIGNED, pendingWith: 'Vijay Mehta', assignedToId: vijay.id,
    },
  ];

  for (const p of promotedVulnSeeds) {
    const created = await prisma.vulnerability.upsert({
      where: { vulnId: p.vulnId },
      update: {},
      create: {
        vulnId: p.vulnId,
        requestId: sr['VA-2026-0001'].id,
        source: RequestSource.VAPT,
        environment: Environment.PRODUCTION,
        type: p.type,
        shortDesc: p.shortDesc,
        description: p.description,
        severity: p.severity,
        cvss: p.cvss,
        cve: p.cve,
        affectedComponent: 'edge-router-fw',
        references: [],
        status: p.status,
        pendingWith: p.pendingWith,
        assignedToId: p.assignedToId,
        poc: p.poc,
        remediation: p.remediation,
        reportedBy: 'VMP Scanner',
        reportedOn: d('May 19, 2026'),
        slaDueDate: p.vulnId === 'VMP-2026-0001' ? d('Jun 01, 2026') : d('Jun 15, 2026'),
        scanFindingId: scanFindings[p.findingId].id,
      },
    });
    createdVulnIds[p.vulnId] = created.id;
  }
  console.log('✅ Promoted Scan Finding Vulnerabilities (2)');

  // ===========================================================================
  // VULNERABILITY LIFECYCLE LOGS — cvs.ts: per-finding `logs[]`
  // ===========================================================================

  type LifecycleLogSeed = {
    vulnId: string;
    fromStatus: VulnerabilityStatus | null;
    toStatus: VulnerabilityStatus;
    actorName: string;
    actorId?: string;
    actorRole: string;
    remarks: string;
    timestamp: Date;
  };

  const lifecycleLogSeeds: LifecycleLogSeed[] = [
    {
      vulnId: 'VMP-2026-0002', fromStatus: VulnerabilityStatus.OPEN, toStatus: VulnerabilityStatus.ASSIGNED,
      actorName: 'System', actorRole: 'Auto-assign', remarks: 'Assigned to Vijay Mehta for remediation.',
      timestamp: d('May 19, 2026 04:05'),
    },
    {
      vulnId: 'VMP-2026-0003', fromStatus: VulnerabilityStatus.OPEN, toStatus: VulnerabilityStatus.ASSIGNED,
      actorName: 'Aanya Sharma', actorId: aanya.id, actorRole: 'Security Lead', remarks: 'Assigned to Rohit Sharma. Critical — SLA: 30 days.',
      timestamp: d('May 19, 2026 09:00'),
    },
    {
      vulnId: 'VMP-2026-0003', fromStatus: VulnerabilityStatus.ASSIGNED, toStatus: VulnerabilityStatus.IN_PROGRESS,
      actorName: 'Rohit Sharma', actorId: rohit.id, actorRole: 'App Owner', remarks: 'Patch development in progress — ETA May 25.',
      timestamp: d('May 20, 2026 10:00'),
    },
    {
      vulnId: 'VMP-2026-0005', fromStatus: VulnerabilityStatus.OPEN, toStatus: VulnerabilityStatus.ASSIGNED,
      actorName: 'Aanya Sharma', actorId: aanya.id, actorRole: 'Security Lead', remarks: 'Assigned to Aanya Sharma — payments-db-cluster owner.',
      timestamp: d('May 19, 2026 08:00'),
    },
    {
      vulnId: 'VMP-2026-0007', fromStatus: VulnerabilityStatus.ASSIGNED, toStatus: VulnerabilityStatus.PATCHED,
      actorName: 'Kiran Dev', actorId: kiranDev.id, actorRole: 'Infra Owner', remarks: 'Regenerated SSH keys — Ed25519 now in use. Patched.',
      timestamp: d('May 16, 2026 11:00'),
    },
  ];

  // VMP-2026-0003..0008 are unpromoted ScanFindings (no Vulnerability row exists
  // for them), so their lifecycle history is recorded against the ScanFinding's
  // *promoted* counterpart only where one exists. Since 0003/0004/0005/0006/0007/0008
  // were never promoted to Vulnerability rows in the mock data, we still want their
  // rich history preserved — store it by creating the log against the nearest
  // promoted Vulnerability when available, otherwise skip gracefully (no FK target).
  // In this dataset, only VMP-2026-0002 has both a Vulnerability row (promoted)
  // and a log; 0003/0005/0007 are unpromoted, so we promote a minimal Vulnerability
  // shadow record for them here to preserve the audit trail without inventing new
  // findings beyond what cvs.ts already describes.
  const shadowPromotions: Array<{ findingId: string; severity: Severity; status: VulnerabilityStatus; pendingWith: string; assignedToId?: string }> = [
    { findingId: 'VMP-2026-0003', severity: Severity.CRITICAL, status: VulnerabilityStatus.IN_PROGRESS, pendingWith: 'Rohit Sharma', assignedToId: rohit.id },
    { findingId: 'VMP-2026-0005', severity: Severity.HIGH, status: VulnerabilityStatus.ASSIGNED, pendingWith: 'Aanya Sharma', assignedToId: aanya.id },
    { findingId: 'VMP-2026-0007', severity: Severity.MEDIUM, status: VulnerabilityStatus.PATCHED, pendingWith: 'Kiran Dev', assignedToId: kiranDev.id },
  ];
  for (const sp of shadowPromotions) {
    const f = scanFindingSeeds.find((x) => x.findingId === sp.findingId)!;
    const created = await prisma.vulnerability.upsert({
      where: { vulnId: sp.findingId },
      update: {},
      create: {
        vulnId: sp.findingId,
        requestId: sr['VA-2026-0001'].id, // grouped under the same VA umbrella for audit continuity
        source: RequestSource.VAPT,
        environment: f.assetEnv,
        type: f.type,
        shortDesc: f.shortDesc,
        description: f.description,
        severity: f.severity,
        cvss: f.cvss,
        cve: f.cve,
        affectedComponent: infra[f.assetKey].serverName,
        references: [],
        status: sp.status,
        pendingWith: sp.pendingWith,
        assignedToId: sp.assignedToId,
        poc: f.poc,
        remediation: f.remediation,
        reportedBy: 'VMP Scanner',
        reportedOn: f.timestamp,
        scanFindingId: scanFindings[sp.findingId].id,
      },
    });
    createdVulnIds[sp.findingId] = created.id;
  }

  // No natural unique key exists on this model, so re-running the seed is made
  // idempotent via an existence check (same vulnerability + toStatus + timestamp)
  // before each create — this prevents duplicate history rows on repeat runs.
  for (const log of lifecycleLogSeeds) {
    const vulnerabilityId = createdVulnIds[log.vulnId];
    if (!vulnerabilityId) continue;
    const existingLog = await prisma.vulnerabilityLifecycleLog.findFirst({
      where: { vulnerabilityId, toStatus: log.toStatus, timestamp: log.timestamp },
    });
    if (existingLog) continue;
    await prisma.vulnerabilityLifecycleLog.create({
      data: {
        vulnerabilityId,
        fromStatus: log.fromStatus,
        toStatus: log.toStatus,
        actorName: log.actorName,
        actorId: log.actorId,
        actorRole: log.actorRole,
        remarks: log.remarks,
        timestamp: log.timestamp,
      },
    });
  }
  console.log(`✅ Vulnerability Lifecycle Logs (${lifecycleLogSeeds.length})`);

  // ===========================================================================
  // ATTACHMENTS — cvs.ts: VMP-2026-0007 log has hasAttachment + attachmentName
  // ===========================================================================

  // Idempotency guard: Attachment has no natural unique key, so check by
  // vulnerabilityId + filename before creating.
  const existingAttachment = await prisma.attachment.findFirst({
    where: { vulnerabilityId: createdVulnIds['VMP-2026-0007'], filename: 'ssh-key-gen-log.txt' },
  });
  if (!existingAttachment) {
    await prisma.attachment.create({
      data: {
        uploadedById: kiranDev.id,
        uploadedByName: 'Kiran Dev',
        vulnerabilityId: createdVulnIds['VMP-2026-0007'],
        filename: 'ssh-key-gen-log.txt',
        mimeType: 'text/plain',
        storageKey: `vuln/VMP-2026-0007/ssh-key-gen-log.txt`,
      },
    });
  }
  console.log('✅ Attachments (1)');

  // ===========================================================================
  // SLA TRACKING — derived 1:1 from each Vulnerability's slaDueDate
  // ===========================================================================

  const allSeededVulns = [...vulnSeeds.map((v) => v.vulnId), ...promotedVulnSeeds.map((v) => v.vulnId), ...shadowPromotions.map((v) => v.findingId)];
  for (const vulnId of allSeededVulns) {
    const vuln = await prisma.vulnerability.findUnique({ where: { vulnId } });
    if (!vuln || !vuln.slaDueDate) continue;
    const now = new Date('2026-06-18'); // seed reference date matches "current date" context
    const daysRemaining = Math.ceil((vuln.slaDueDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
    const isBreached = vuln.slaDueDate.getTime() < now.getTime() && vuln.status !== VulnerabilityStatus.CLOSED;
    await prisma.slaTracking.upsert({
      where: { vulnerabilityId: vuln.id },
      update: {},
      create: {
        vulnerabilityId: vuln.id,
        dueDate: vuln.slaDueDate,
        isBreached,
        breachedAt: isBreached ? vuln.slaDueDate : null,
        daysRemaining,
      },
    });
  }
  console.log('✅ SLA Tracking');

  // ===========================================================================
  // COMMENTS — vapt.ts: VAPT-2025-0042 has 2 real comments
  // ===========================================================================

  // Idempotency guard: Comment has no natural unique key, so check by
  // requestId + createdAt timestamp before creating.
  const existingComment1 = await prisma.comment.findFirst({
    where: { requestId: sr['VAPT-2025-0042'].id, createdAt: d('Mar 14, 2026 09:12:04') },
  });
  if (!existingComment1) {
    await prisma.comment.create({
      data: {
        authorId: aanya.id, // SecureLayer7 acts as an external lead assessor; logged under the internal coordinator
        authorName: 'SecureLayer7 (Lead Assessor)',
        authorRole: 'External Assessor',
        requestId: sr['VAPT-2025-0042'].id,
        body: 'Assessment completed. 48 findings reported across Critical, High, Medium and Low categories. Full report shared via secure email to Rohit Sharma.',
        createdAt: d('Mar 14, 2026 09:12:04'),
      },
    });
  }
  const existingComment2 = await prisma.comment.findFirst({
    where: { requestId: sr['VAPT-2025-0042'].id, createdAt: d('Mar 16, 2026 11:30:22') },
  });
  if (!existingComment2) {
    await prisma.comment.create({
      data: {
        authorId: rohit.id,
        authorName: 'Rohit Sharma (App Owner)',
        authorRole: 'Application Owner',
        requestId: sr['VAPT-2025-0042'].id,
        body: 'Acknowledged. Platform team triage in progress. Critical findings being addressed on priority.',
        createdAt: d('Mar 16, 2026 11:30:22'),
      },
    });
  }
  console.log('✅ Comments (2)');

  // ===========================================================================
  // SLA POLICIES — global per-severity policy, not present in frontend mocks but
  // required by the platform to compute the slaTracking/daysRemaining figures
  // referenced throughout (e.g. 30-day Critical SLA matches VAPT-2025-0042-001).
  // ===========================================================================

  for (const p of [
    { severity: Severity.CRITICAL, slaDays: 30, description: 'Critical: remediate within 30 days' },
    { severity: Severity.HIGH, slaDays: 45, description: 'High: remediate within 45 days' },
    { severity: Severity.MEDIUM, slaDays: 90, description: 'Medium: remediate within 90 days' },
    { severity: Severity.LOW, slaDays: 180, description: 'Low: remediate within 180 days' },
    { severity: Severity.INFORMATIONAL, slaDays: 365, description: 'Informational: review within 365 days' },
  ]) {
    await prisma.slaPolicy.upsert({ where: { severity: p.severity }, update: { slaDays: p.slaDays }, create: p });
  }
  console.log('✅ SLA Policies');

  // ===========================================================================
  // PLATFORM SETTINGS — dashboard summary figures from requests.ts
  // (PENDING_COUNT, TOTAL_ACTIVE, SLA_STATUS, OVERDUE_COUNT), stored as
  // reporting-category settings so the dashboard can read live or fall back here.
  // ===========================================================================

  for (const s of [
    { category: SettingCategory.GENERAL, key: 'platform.name', value: 'Sentinel SLM', dataType: SettingDataType.STRING, label: 'Platform Name', isEditable: false },
    { category: SettingCategory.GENERAL, key: 'platform.version', value: '1.0.0', dataType: SettingDataType.STRING, label: 'Platform Version', isEditable: false },
    { category: SettingCategory.SECURITY, key: 'security.max_login_attempts', value: '5', dataType: SettingDataType.INTEGER, label: 'Max Login Attempts' },
    { category: SettingCategory.SECURITY, key: 'security.lockout_duration_minutes', value: '30', dataType: SettingDataType.INTEGER, label: 'Lockout Duration (minutes)' },
    { category: SettingCategory.NOTIFICATIONS, key: 'notifications.email_enabled', value: 'true', dataType: SettingDataType.BOOLEAN, label: 'Email Notifications' },
    { category: SettingCategory.REPORTING, key: 'dashboard.total_active_requests', value: '66', dataType: SettingDataType.INTEGER, label: 'Total Active Requests (cached)' },
    { category: SettingCategory.REPORTING, key: 'dashboard.sla_status_pct', value: '89', dataType: SettingDataType.INTEGER, label: 'Overall SLA Compliance % (cached)' },
    { category: SettingCategory.REPORTING, key: 'dashboard.overdue_count', value: '7', dataType: SettingDataType.INTEGER, label: 'Overdue Requests (cached)' },
    { category: SettingCategory.AI, key: 'ai.enabled', value: 'true', dataType: SettingDataType.BOOLEAN, label: 'Enable AI Features' },
    { category: SettingCategory.AI, key: 'ai.provider', value: 'OPENROUTER', dataType: SettingDataType.STRING, label: 'AI Provider' },
    { category: SettingCategory.AI, key: 'ai.apiKey', value: '', dataType: SettingDataType.STRING, label: 'API Key' },
    { category: SettingCategory.AI, key: 'ai.model', value: 'google/gemini-2.5-flash', dataType: SettingDataType.STRING, label: 'AI Model' },
    { category: SettingCategory.AI, key: 'ai.temperature', value: '0.2', dataType: SettingDataType.STRING, label: 'Temperature' },
    { category: SettingCategory.AI, key: 'ai.maxTokens', value: '1024', dataType: SettingDataType.INTEGER, label: 'Max Output Tokens' },
    { category: SettingCategory.AI, key: 'ai.timeoutMs', value: '30000', dataType: SettingDataType.INTEGER, label: 'Request Timeout (ms)' },
  ]) {
    await prisma.platformSetting.upsert({ where: { key: s.key }, update: { value: s.value }, create: s });
  }
  console.log('✅ Platform Settings');

  // ===========================================================================
  // AUDIT LOGS — a minimal, representative trail for the auto-created VA request
  // (cvs.ts createVaRequest()/vaRequests[0].logs) so AuditLog has real coverage.
  // ===========================================================================

  // Idempotency guard: AuditLog has no natural unique key, so check by
  // entityId + action + timestamp before creating.
  const existingAudit1 = await prisma.auditLog.findFirst({
    where: { entityId: sr['VA-2026-0001'].id, action: AuditAction.CREATED, timestamp: d('May 19, 2026 08:05') },
  });
  if (!existingAudit1) {
    await prisma.auditLog.create({
      data: {
        actorName: 'System',
        entityType: AuditEntityType.SECURITY_REQUEST,
        entityId: sr['VA-2026-0001'].id,
        action: AuditAction.CREATED,
        after: {
          reqId: 'VA-2026-0001',
          note: 'VA Request VA-2026-0001 auto-created from 2 CVS findings for edge-router-fw.',
          vulnIds: ['VMP-2026-0001', 'VMP-2026-0002'],
          source: 'VMP scanner',
        },
        metadata: { source: 'VMP scanner' },
        timestamp: d('May 19, 2026 08:05'),
      },
    });
  }
  const existingAudit2 = await prisma.auditLog.findFirst({
    where: { entityId: sr['VA-2026-0001'].id, action: AuditAction.ASSIGNED, timestamp: d('May 19, 2026 08:05') },
  });
  if (!existingAudit2) {
    await prisma.auditLog.create({
      data: {
        actorName: 'System',
        entityType: AuditEntityType.SECURITY_REQUEST,
        entityId: sr['VA-2026-0001'].id,
        action: AuditAction.ASSIGNED,
        after: {
          note: 'Both vulnerabilities assigned to Vijay Mehta (Asset Owner, SRV-0001).',
          basis: 'Assignment based on infra ownership registry.',
        },
        metadata: { source: 'VMP scanner' },
        timestamp: d('May 19, 2026 08:05'),
      },
    });
  }
  console.log('✅ Audit Logs (2)');

  // ===========================================================================
  // SECURITY CONTROLS — Canonical control taxonomy
  // Idempotent: upsert on controlKey. Re-running the seed never creates duplicates.
  // ===========================================================================

  const controlDefs: Array<{
    controlKey: string;
    name: string;
    description: string;
    category: import('@prisma/client').SecurityControlCategory;
  }> = [
    {
      controlKey: 'PATCH_MGMT',
      name: 'Patch Management',
      description: 'OS, middleware, package and firmware patching — ensures all components run supported, up-to-date versions.',
      category: 'INFRASTRUCTURE',
    },
    {
      controlKey: 'AUTH_CONTROLS',
      name: 'Authentication & Access Control',
      description: 'Identity verification, MFA enforcement, session management, least-privilege access.',
      category: 'APPLICATION',
    },
    {
      controlKey: 'SECURE_CONFIG',
      name: 'Secure Configuration',
      description: 'Hardening of OS, services and application frameworks against default or insecure settings.',
      category: 'INFRASTRUCTURE',
    },
    {
      controlKey: 'LOGGING_MONITORING',
      name: 'Logging & Monitoring',
      description: 'Centralised log collection, SIEM integration, alerting and audit-trail completeness.',
      category: 'GOVERNANCE',
    },
    {
      controlKey: 'SECRETS_MGMT',
      name: 'Secrets Management',
      description: 'Secure storage and rotation of credentials, API keys, certificates and other secrets.',
      category: 'APPLICATION',
    },
    {
      controlKey: 'ENCRYPTION',
      name: 'Encryption & TLS',
      description: 'Data-at-rest and data-in-transit encryption, TLS version and cipher-suite compliance.',
      category: 'DATA',
    },
    {
      controlKey: 'NETWORK_SECURITY',
      name: 'Network Security',
      description: 'Firewall rules, network segmentation, exposure of unnecessary ports and services.',
      category: 'INFRASTRUCTURE',
    },
    {
      controlKey: 'CLOUD_SECURITY',
      name: 'Cloud Security',
      description: 'Cloud-native posture management — misconfigured buckets, IAM over-permissions, public exposure.',
      category: 'CLOUD',
    },
    {
      controlKey: 'ASSET_MGMT',
      name: 'Asset Management',
      description: 'Inventory completeness, criticality classification and lifecycle tracking of all assets.',
      category: 'GOVERNANCE',
    },
    {
      controlKey: 'INPUT_VALIDATION',
      name: 'Input Validation & Injection Prevention',
      description: 'SQL injection, XSS, SSRF, path traversal and other input-handling vulnerabilities.',
      category: 'APPLICATION',
    },
    {
      controlKey: 'INCIDENT_RESPONSE',
      name: 'Incident Response',
      description: 'Preparedness, playbooks, detection-to-containment time and post-incident review maturity.',
      category: 'GOVERNANCE',
    },
  ];

  const controls: Record<string, Awaited<ReturnType<typeof prisma.securityControl.upsert>>> = {};
  for (const c of controlDefs) {
    controls[c.controlKey] = await prisma.securityControl.upsert({
      where: { controlKey: c.controlKey },
      update: { name: c.name, description: c.description, category: c.category, isActive: true },
      create: {
        controlKey: c.controlKey,
        name: c.name,
        description: c.description,
        category: c.category,
        isActive: true,
      },
    });
  }
  console.log(`✅ Security Controls (${Object.keys(controls).length})`);

  // ===========================================================================
  // COMPLIANCE FRAMEWORKS + FRAMEWORK CONTROLS
  // 4 frameworks seeded. FrameworkControl rows map each framework's own control
  // reference ID (e.g. "CIS-7.3") to one of our SecurityControl records.
  // Only representative mappings are seeded here — the full set is a data task.
  // ===========================================================================

  type FwDef = {
    frameworkKey: import('@prisma/client').ComplianceFrameworkKey;
    name: string;
    version: string;
    description: string;
    mappings: Array<{ controlKey: string; frameworkControlId: string; description?: string }>;
  };

  const frameworkDefs: FwDef[] = [
    {
      frameworkKey: 'CIS_CONTROLS_V8',
      name: 'CIS Controls',
      version: 'v8.0',
      description: 'Center for Internet Security Critical Security Controls — 18 control groups for defensive security.',
      mappings: [
        { controlKey: 'ASSET_MGMT',      frameworkControlId: 'CIS-1',  description: 'Inventory and Control of Enterprise Assets' },
        { controlKey: 'PATCH_MGMT',      frameworkControlId: 'CIS-2',  description: 'Inventory and Control of Software Assets' },
        { controlKey: 'PATCH_MGMT',      frameworkControlId: 'CIS-7',  description: 'Continuous Vulnerability Management' },
        { controlKey: 'AUTH_CONTROLS',   frameworkControlId: 'CIS-5',  description: 'Account Management' },
        { controlKey: 'AUTH_CONTROLS',   frameworkControlId: 'CIS-6',  description: 'Access Control Management' },
        { controlKey: 'SECURE_CONFIG',   frameworkControlId: 'CIS-4',  description: 'Secure Configuration of Enterprise Assets and Software' },
        { controlKey: 'LOGGING_MONITORING', frameworkControlId: 'CIS-8', description: 'Audit Log Management' },
        { controlKey: 'NETWORK_SECURITY',frameworkControlId: 'CIS-12', description: 'Network Infrastructure Management' },
        { controlKey: 'ENCRYPTION',      frameworkControlId: 'CIS-3',  description: 'Data Protection' },
        { controlKey: 'SECRETS_MGMT',    frameworkControlId: 'CIS-5',  description: 'Account Management — credentials' },
        { controlKey: 'CLOUD_SECURITY',  frameworkControlId: 'CIS-16', description: 'Application Software Security' },
        { controlKey: 'INPUT_VALIDATION',frameworkControlId: 'CIS-16', description: 'Application Software Security — input handling' },
        { controlKey: 'INCIDENT_RESPONSE',frameworkControlId:'CIS-17', description: 'Incident Response Management' },
      ],
    },
    {
      frameworkKey: 'NIST_CSF_2',
      name: 'NIST Cybersecurity Framework',
      version: '2.0',
      description: 'NIST CSF 2.0 — Govern, Identify, Protect, Detect, Respond, Recover functions.',
      mappings: [
        { controlKey: 'ASSET_MGMT',       frameworkControlId: 'NIST-ID.AM',  description: 'Asset Management' },
        { controlKey: 'PATCH_MGMT',       frameworkControlId: 'NIST-ID.RA',  description: 'Risk Assessment — vulnerability mgmt' },
        { controlKey: 'AUTH_CONTROLS',    frameworkControlId: 'NIST-PR.AA',  description: 'Identity Management & Access Control' },
        { controlKey: 'SECURE_CONFIG',    frameworkControlId: 'NIST-PR.PS',  description: 'Platform Security — configuration' },
        { controlKey: 'LOGGING_MONITORING',frameworkControlId:'NIST-DE.CM',  description: 'Continuous Monitoring' },
        { controlKey: 'ENCRYPTION',       frameworkControlId: 'NIST-PR.DS',  description: 'Data Security — encryption' },
        { controlKey: 'NETWORK_SECURITY', frameworkControlId: 'NIST-PR.IR',  description: 'Technology Infrastructure Resilience' },
        { controlKey: 'SECRETS_MGMT',     frameworkControlId: 'NIST-PR.AA',  description: 'Identity Management — secrets' },
        { controlKey: 'INCIDENT_RESPONSE',frameworkControlId: 'NIST-RS.MA',  description: 'Incident Management' },
        { controlKey: 'CLOUD_SECURITY',   frameworkControlId: 'NIST-PR.PS',  description: 'Platform Security — cloud posture' },
        { controlKey: 'INPUT_VALIDATION', frameworkControlId: 'NIST-PR.PS',  description: 'Platform Security — secure development' },
      ],
    },
    {
      frameworkKey: 'ISO_27001_2022',
      name: 'ISO/IEC 27001',
      version: '2022',
      description: 'ISO/IEC 27001:2022 — Information Security Management System controls (Annex A).',
      mappings: [
        { controlKey: 'ASSET_MGMT',        frameworkControlId: 'ISO-A.5.9',   description: 'Inventory of information and other associated assets' },
        { controlKey: 'PATCH_MGMT',        frameworkControlId: 'ISO-A.8.8',   description: 'Management of technical vulnerabilities' },
        { controlKey: 'AUTH_CONTROLS',     frameworkControlId: 'ISO-A.5.15',  description: 'Access control' },
        { controlKey: 'SECURE_CONFIG',     frameworkControlId: 'ISO-A.8.9',   description: 'Configuration management' },
        { controlKey: 'LOGGING_MONITORING',frameworkControlId: 'ISO-A.8.15',  description: 'Logging' },
        { controlKey: 'ENCRYPTION',        frameworkControlId: 'ISO-A.8.24',  description: 'Use of cryptography' },
        { controlKey: 'NETWORK_SECURITY',  frameworkControlId: 'ISO-A.8.20',  description: 'Networks security' },
        { controlKey: 'SECRETS_MGMT',      frameworkControlId: 'ISO-A.8.25',  description: 'Secure development life cycle — credential hygiene' },
        { controlKey: 'CLOUD_SECURITY',    frameworkControlId: 'ISO-A.5.23',  description: 'Information security for use of cloud services' },
        { controlKey: 'INPUT_VALIDATION',  frameworkControlId: 'ISO-A.8.28',  description: 'Secure coding' },
        { controlKey: 'INCIDENT_RESPONSE', frameworkControlId: 'ISO-A.5.26',  description: 'Response to information security incidents' },
      ],
    },
    {
      frameworkKey: 'PCI_DSS_V4',
      name: 'PCI DSS',
      version: 'v4.0',
      description: 'Payment Card Industry Data Security Standard v4.0 — 12 requirements for cardholder data protection.',
      mappings: [
        { controlKey: 'NETWORK_SECURITY',  frameworkControlId: 'PCI-1',  description: 'Install and Maintain Network Security Controls' },
        { controlKey: 'SECURE_CONFIG',     frameworkControlId: 'PCI-2',  description: 'Apply Secure Configurations to All System Components' },
        { controlKey: 'ENCRYPTION',        frameworkControlId: 'PCI-3',  description: 'Protect Account Data — encryption at rest/transit' },
        { controlKey: 'ENCRYPTION',        frameworkControlId: 'PCI-4',  description: 'Protect Cardholder Data with Strong Cryptography' },
        { controlKey: 'PATCH_MGMT',        frameworkControlId: 'PCI-6',  description: 'Develop and Maintain Secure Systems and Software' },
        { controlKey: 'INPUT_VALIDATION',  frameworkControlId: 'PCI-6',  description: 'Develop and Maintain Secure Systems — input validation' },
        { controlKey: 'AUTH_CONTROLS',     frameworkControlId: 'PCI-7',  description: 'Restrict Access to System Components and Cardholder Data' },
        { controlKey: 'AUTH_CONTROLS',     frameworkControlId: 'PCI-8',  description: 'Identify Users and Authenticate Access to System Components' },
        { controlKey: 'LOGGING_MONITORING',frameworkControlId: 'PCI-10', description: 'Log and Monitor All Access to System Components and Cardholder Data' },
        { controlKey: 'PATCH_MGMT',        frameworkControlId: 'PCI-11', description: 'Test Security of Systems and Networks Regularly' },
        { controlKey: 'INCIDENT_RESPONSE', frameworkControlId: 'PCI-12', description: 'Support Information Security with Organizational Policies and Programs' },
      ],
    },
  ];

  for (const fw of frameworkDefs) {
    const framework = await prisma.complianceFramework.upsert({
      where: { frameworkKey: fw.frameworkKey },
      update: { name: fw.name, version: fw.version, description: fw.description, isActive: true },
      create: {
        frameworkKey: fw.frameworkKey,
        name: fw.name,
        version: fw.version,
        description: fw.description,
        isActive: true,
      },
    });

    // Upsert FrameworkControl rows — one per (framework, control) pair.
    // Some frameworks map multiple frameworkControlIds to the same control;
    // the @@unique([frameworkId, controlId]) constraint keeps one row per pair,
    // so we update frameworkControlId + description on conflict.
    for (const m of fw.mappings) {
      const ctrl = controls[m.controlKey];
      if (!ctrl) continue;
      await prisma.frameworkControl.upsert({
        where: {
          frameworkId_controlId: {
            frameworkId: framework.id,
            controlId: ctrl.id,
          },
        },
        update: { frameworkControlId: m.frameworkControlId, description: m.description },
        create: {
          frameworkId: framework.id,
          controlId: ctrl.id,
          frameworkControlId: m.frameworkControlId,
          description: m.description,
        },
      });
    }
  }
  console.log(`✅ Compliance Frameworks (${frameworkDefs.length}) + Framework Controls`);

  // ===========================================================================
  // SUMMARY
  // ===========================================================================

  console.table(
    await prisma.application.findMany({
      select: {
        appId: true,
        name: true,
      }
    })
  );

  console.log('\n🎉 Seed complete.');
}

main()
  .catch((e) => {
    console.error('❌ Seed failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });