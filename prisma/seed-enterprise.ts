// =============================================================================
// Sentinel SLM – Enterprise Demo Seed  (Wave 1: Foundation)
// Run: npx ts-node --project tsconfig.json prisma/seed-enterprise.ts
// Safe to re-run — uses upsert + skipDuplicates throughout.
// =============================================================================

import {
  PrismaClient, UserRole, Environment, AssetType,
  InfraType, CloudProvider, CloudResourceType,
  RequestStatus, Severity, FindingStatus, VulnerabilityStatus,
  SettingCategory, SettingDataType
} from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  console.log('🏢 Sentinel SLM — Wave 1: Enterprise Foundation');
  
  // Clean transactional tables to ensure perfect idempotency
  await prisma.vulnerabilityLifecycleLog.deleteMany();
  await prisma.slaTracking.deleteMany();
  await prisma.vulnerability.deleteMany();

  await prisma.securityRequest.deleteMany();
  await prisma.appCloudResource.deleteMany();
  await prisma.appInfrastructureAsset.deleteMany();
  await prisma.cloudResource.deleteMany();
  await prisma.cloudAccount.deleteMany();
  await prisma.infrastructureAsset.deleteMany();
  await prisma.application.deleteMany();

  const hash = await bcrypt.hash('Sentinel@2024', 10);

  // ── 1. USERS (50) ─────────────────────────────────────────────────────────
  const uDefs = [
    // Security Leads (3)
    { email:'aanya.sharma@msil.in',     name:'Aanya Sharma',         sid:'EMP-1101', dept:'Security Operations', role:UserRole.SECURITY_LEAD },
    { email:'rajiv.menon@msil.in',      name:'Rajiv Menon',          sid:'EMP-1102', dept:'Security Operations', role:UserRole.SECURITY_LEAD },
    { email:'deepa.pillai@msil.in',     name:'Deepa Pillai',         sid:'EMP-1103', dept:'Security Operations', role:UserRole.SECURITY_LEAD },
    // Security Analysts (10)
    { email:'analyst@sentinel.local',   name:'Priya Sharma',         sid:'SLM-002',  dept:'Security',            role:UserRole.SECURITY_ANALYST },
    { email:'arjun.bose@msil.in',       name:'Arjun Bose',           sid:'EMP-2101', dept:'SOC',                 role:UserRole.SECURITY_ANALYST },
    { email:'lakshmi.iyer@msil.in',     name:'Lakshmi Iyer',         sid:'EMP-2102', dept:'SOC',                 role:UserRole.SECURITY_ANALYST },
    { email:'mohit.saxena@msil.in',     name:'Mohit Saxena',         sid:'EMP-2103', dept:'VAPT',                role:UserRole.SECURITY_ANALYST },
    { email:'sneha.gupta@msil.in',      name:'Sneha Gupta',          sid:'EMP-2104', dept:'VAPT',                role:UserRole.SECURITY_ANALYST },
    { email:'ashwin.rao@msil.in',       name:'Ashwin Rao',           sid:'EMP-2105', dept:'SOC',                 role:UserRole.SECURITY_ANALYST },
    { email:'divya.nair@msil.in',       name:'Divya Nair',           sid:'EMP-2106', dept:'Threat Intelligence', role:UserRole.SECURITY_ANALYST },
    { email:'karthik.sub@msil.in',      name:'Karthik Subramanian',  sid:'EMP-2107', dept:'SOC',                 role:UserRole.SECURITY_ANALYST },
    { email:'pooja.mishra@msil.in',     name:'Pooja Mishra',         sid:'EMP-2108', dept:'SOC',                 role:UserRole.SECURITY_ANALYST },
    { email:'rahul.pandey@msil.in',     name:'Rahul Pandey',         sid:'EMP-2109', dept:'VAPT',                role:UserRole.SECURITY_ANALYST },
    { email:'sanjay.kulkarni@msil.in',  name:'Sanjay Kulkarni',      sid:'EMP-2110', dept:'VAPT',                role:UserRole.SECURITY_ANALYST },
    // Application Owners (15)
    { email:'rohit.sharma@msil.in',     name:'Rohit Sharma',         sid:'EMP-4210', dept:'Platform',            role:UserRole.APPLICATION_OWNER },
    { email:'meera.krishnan@msil.in',   name:'Meera Krishnan',       sid:'EMP-0712', dept:'Security',            role:UserRole.APPLICATION_OWNER },
    { email:'priya.verma@msil.in',      name:'Priya Verma',          sid:'EMP-2801', dept:'Analytics',           role:UserRole.APPLICATION_OWNER },
    { email:'jai.tiwari@msil.in',       name:'Jai Tiwari',           sid:'EMP-5301', dept:'Risk & Compliance',   role:UserRole.APPLICATION_OWNER },
    { email:'suresh.nair@msil.in',      name:'Suresh Nair',          sid:'EMP-6101', dept:'IT Ops',              role:UserRole.APPLICATION_OWNER },
    { email:'anita.desai@msil.in',      name:'Anita Desai',          sid:'EMP-3201', dept:'Core Banking',        role:UserRole.APPLICATION_OWNER },
    { email:'vikram.singh@msil.in',     name:'Vikram Singh',         sid:'EMP-3202', dept:'Digital Products',    role:UserRole.APPLICATION_OWNER },
    { email:'sunita.patil@msil.in',     name:'Sunita Patil',         sid:'EMP-3203', dept:'Core Banking',        role:UserRole.APPLICATION_OWNER },
    { email:'ravi.joshi@msil.in',       name:'Ravi Joshi',           sid:'EMP-3204', dept:'Digital Products',    role:UserRole.APPLICATION_OWNER },
    { email:'kavita.reddy@msil.in',     name:'Kavita Reddy',         sid:'EMP-3205', dept:'Corporate IT',        role:UserRole.APPLICATION_OWNER },
    { email:'amit.kapoor@msil.in',      name:'Amit Kapoor',          sid:'EMP-3206', dept:'Corporate IT',        role:UserRole.APPLICATION_OWNER },
    { email:'neha.agarwal@msil.in',     name:'Neha Agarwal',         sid:'EMP-3207', dept:'Core Banking',        role:UserRole.APPLICATION_OWNER },
    { email:'sunil.mathur@msil.in',     name:'Sunil Mathur',         sid:'EMP-3208', dept:'Trade Finance',       role:UserRole.APPLICATION_OWNER },
    { email:'radha.k@msil.in',          name:'Radha Krishnamurthy',  sid:'EMP-3209', dept:'Digital Products',    role:UserRole.APPLICATION_OWNER },
    { email:'tarun.ahuja@msil.in',      name:'Tarun Ahuja',          sid:'EMP-3210', dept:'DevOps',              role:UserRole.APPLICATION_OWNER },
    // Infrastructure Owners (14)
    { email:'vijay.mehta@msil.in',      name:'Vijay Mehta',          sid:'EMP-3301', dept:'Network Security',    role:UserRole.INFRASTRUCTURE_OWNER },
    { email:'kiran.dev@msil.in',        name:'Kiran Dev',            sid:'EMP-4101', dept:'DevOps',              role:UserRole.INFRASTRUCTURE_OWNER },
    { email:'narayan.iyengar@msil.in',  name:'Narayan Iyengar',      sid:'EMP-4102', dept:'Infrastructure',      role:UserRole.INFRASTRUCTURE_OWNER },
    { email:'sudha.venkat@msil.in',     name:'Sudha Venkataraman',   sid:'EMP-4103', dept:'Infrastructure',      role:UserRole.INFRASTRUCTURE_OWNER },
    { email:'ganesh.moorthy@msil.in',   name:'Ganesh Moorthy',       sid:'EMP-4104', dept:'Network Ops',         role:UserRole.INFRASTRUCTURE_OWNER },
    { email:'prasad.hegde@msil.in',     name:'Prasad Hegde',         sid:'EMP-4105', dept:'Cloud Ops',           role:UserRole.INFRASTRUCTURE_OWNER },
    { email:'lalitha.c@msil.in',        name:'Lalitha Chakrabarti',  sid:'EMP-4106', dept:'Cloud Ops',           role:UserRole.INFRASTRUCTURE_OWNER },
    { email:'biju.thomas@msil.in',      name:'Biju Thomas',          sid:'EMP-4107', dept:'DC Operations',       role:UserRole.INFRASTRUCTURE_OWNER },
    { email:'sridhar.n@msil.in',        name:'Sridhar Narayanan',    sid:'EMP-4108', dept:'Infrastructure',      role:UserRole.INFRASTRUCTURE_OWNER },
    { email:'usha.bala@msil.in',        name:'Usha Balakrishnan',    sid:'EMP-4109', dept:'Storage & Backup',    role:UserRole.INFRASTRUCTURE_OWNER },
    { email:'manoj.pillai@msil.in',     name:'Manoj Pillai',         sid:'EMP-4110', dept:'Network Ops',         role:UserRole.INFRASTRUCTURE_OWNER },
    { email:'girish.nayak@msil.in',     name:'Girish Nayak',         sid:'EMP-4111', dept:'Cloud Ops',           role:UserRole.INFRASTRUCTURE_OWNER },
    { email:'sudhir.rao@msil.in',       name:'Sudhir Rao',           sid:'EMP-4112', dept:'DC Operations',       role:UserRole.INFRASTRUCTURE_OWNER },
    { email:'malathi.sub@msil.in',      name:'Malathi Subramaniam',  sid:'EMP-4113', dept:'Network Security',    role:UserRole.INFRASTRUCTURE_OWNER },
    // Read Only / Audit (8)
    { email:'readonly@sentinel.local',  name:'Vikram Das',           sid:'SLM-005',  dept:'Audit',               role:UserRole.READ_ONLY },
    { email:'chief.audit@msil.in',      name:'Shantha Gopalan',      sid:'EMP-7001', dept:'Internal Audit',      role:UserRole.READ_ONLY },
    { email:'risk.officer@msil.in',     name:'Venkat Raman',         sid:'EMP-7002', dept:'Risk Management',     role:UserRole.READ_ONLY },
    { email:'ciso.office@msil.in',      name:'Ramesh Balaji',        sid:'EMP-7003', dept:'CISO Office',         role:UserRole.READ_ONLY },
    { email:'compliance.head@msil.in',  name:'Malathi Nair',         sid:'EMP-7004', dept:'Compliance',          role:UserRole.READ_ONLY },
    { email:'external.audit@msil.in',   name:'Suresh Parthasarathy', sid:'EMP-7005', dept:'External Audit',      role:UserRole.READ_ONLY },
    { email:'board.rep@msil.in',        name:'Pradeep Krishnaswamy', sid:'EMP-7006', dept:'Board Office',        role:UserRole.READ_ONLY },
    { email:'rbi.liaison@msil.in',      name:'Ananya Iyer',          sid:'EMP-7007', dept:'Regulatory Affairs',  role:UserRole.READ_ONLY },
  ];

  const uMap: Record<string, string> = {};
  for (const u of uDefs) {
    const r = await prisma.user.upsert({
      where:  { email: u.email },
      update: { name: u.name, staffId: u.sid, department: u.dept, role: u.role },
      create: { email: u.email, name: u.name, staffId: u.sid, department: u.dept, passwordHash: hash, role: u.role, isActive: true },
    });
    uMap[u.email] = r.id;
  }
  console.log(`✅ Users (${uDefs.length})`);
  const uid = (e: string) => uMap[e] ?? uMap['aanya.sharma@msil.in'];

  // ── 2. APPLICATIONS (30) ──────────────────────────────────────────────────
  type AD = { appId:string; name:string; desc:string; type:AssetType; env:Environment; dept:string; crit:string; cls:string; oe:string; net:boolean; pii:boolean; bia:boolean; url?:string; pre?:string; vs?:string; nv?:Date };
  const aDefs: AD[] = [
    // Legacy Monoliths (3)
    { appId:'APP-E001', name:'core-banking-system-v1',       desc:'Legacy AS/400 monolithic core banking engine',                             type:AssetType.WEB_APPLICATION, env:Environment.PRODUCTION,     dept:'Core Banking',     crit:'Critical', cls:'Internal',        oe:'anita.desai@msil.in',    net:false, pii:true,  bia:true,  url:'https://core-v1.msil.in',                                        vs:'Overdue',   nv:new Date('2026-06-30') },
    { appId:'APP-E002', name:'legacy-erp-portal',            desc:'Legacy on-premise ERP system for supply chain and finance',                type:AssetType.WEB_APPLICATION, env:Environment.PRODUCTION,     dept:'Corporate IT',     crit:'High',     cls:'Internal',        oe:'kavita.reddy@msil.in',   net:false, pii:true,  bia:true,  url:'https://erp.msil.in',                                            vs:'Due',       nv:new Date('2026-07-15') },
    { appId:'APP-E003', name:'mainframe-payment-switch',     desc:'Legacy payment switch handling batch settlements',                         type:AssetType.WEB_APPLICATION, env:Environment.PRODUCTION,     dept:'Core Banking',     crit:'Critical', cls:'Internal',        oe:'anita.desai@msil.in',    net:false, pii:true,  bia:true,  url:'https://switch.msil.in',                                         vs:'Scheduled', nv:new Date('2026-08-01') },
    // Enterprise Web Apps (5)
    { appId:'APP-E004', name:'internet-banking-portal',      desc:'Modern customer-facing internet banking platform',                         type:AssetType.WEB_APPLICATION, env:Environment.PRODUCTION,     dept:'Digital Products', crit:'Critical', cls:'Internet Facing', oe:'vikram.singh@msil.in',   net:true,  pii:true,  bia:true,  url:'https://banking.msil.in',                                        vs:'Scheduled', nv:new Date('2026-08-15') },
    { appId:'APP-E005', name:'trade-finance-portal',         desc:'LC, Bank Guarantees, and Trade Finance workflow management',               type:AssetType.WEB_APPLICATION, env:Environment.PRODUCTION,     dept:'Trade Finance',    crit:'High',     cls:'Internet Facing', oe:'sunil.mathur@msil.in',   net:true,  pii:true,  bia:true,  url:'https://tradefinance.msil.in',                                   vs:'Scheduled', nv:new Date('2026-09-01') },
    { appId:'APP-E006', name:'customer-360-portal',          desc:'360-degree customer intelligence and relationship management',             type:AssetType.WEB_APPLICATION, env:Environment.PRODUCTION,     dept:'Digital Products', crit:'High',     cls:'Internal',        oe:'ravi.joshi@msil.in',     net:false, pii:true,  bia:false, url:'https://c360.msil.in',                                           vs:'Overdue',   nv:new Date('2026-06-15') },
    { appId:'APP-E007', name:'dealer-management-system',     desc:'Dealer network onboarding, inventory, and commission management',          type:AssetType.WEB_APPLICATION, env:Environment.PRODUCTION,     dept:'Corporate IT',     crit:'Medium',   cls:'Internet Facing', oe:'rohit.sharma@msil.in',   net:true,  pii:true,  bia:false, url:'https://dealers.msil.in',                                        vs:'Scheduled', nv:new Date('2026-10-15') },
    { appId:'APP-E008', name:'loan-origination-platform',    desc:'Loan lifecycle: application, credit assessment, disbursement, servicing',  type:AssetType.WEB_APPLICATION, env:Environment.PRE_PRODUCTION, dept:'Core Banking',     crit:'High',     cls:'Internal',        oe:'neha.agarwal@msil.in',   net:false, pii:true,  bia:true,  url:'https://loans-uat.msil.in',                                      vs:'Scheduled', nv:new Date('2026-09-01') },
    // Internal Business Portals (3)
    { appId:'APP-E009', name:'hrms',                         desc:'HR Management: payroll, leave, attendance, appraisal, workforce',          type:AssetType.WEB_APPLICATION, env:Environment.PRODUCTION,     dept:'Corporate IT',     crit:'Medium',   cls:'Internal',        oe:'kavita.reddy@msil.in',   net:false, pii:true,  bia:false, url:'https://hrms.msil.in',                                           vs:'Scheduled', nv:new Date('2026-10-01') },
    { appId:'APP-E010', name:'corporate-intranet',           desc:'Internal knowledge base, announcements, and employee self-service',        type:AssetType.WEB_APPLICATION, env:Environment.PRODUCTION,     dept:'Corporate IT',     crit:'Low',      cls:'Internal',        oe:'amit.kapoor@msil.in',    net:false, pii:false, bia:false, url:'https://intranet.msil.in',                                       vs:'Scheduled', nv:new Date('2026-11-15') },
    { appId:'APP-E011', name:'compliance-portal',            desc:'Regulatory compliance tracking, RBI/SEBI reporting, and audit workflows',  type:AssetType.WEB_APPLICATION, env:Environment.PRODUCTION,     dept:'Risk & Compliance', crit:'High',     cls:'Internal',        oe:'jai.tiwari@msil.in',     net:false, pii:true,  bia:false, url:'https://compliance.msil.in',                                     vs:'Scheduled', nv:new Date('2026-09-01') },
    // Public APIs (3)
    { appId:'APP-E012', name:'mobile-banking-api',           desc:'Core REST API powering iOS and Android mobile banking apps',               type:AssetType.API,             env:Environment.PRODUCTION,     dept:'Core Banking',     crit:'Critical', cls:'Internet Facing', oe:'sunita.patil@msil.in',   net:true,  pii:true,  bia:true,  url:'https://api.banking.msil.in',                                    vs:'Scheduled', nv:new Date('2026-08-01') },
    { appId:'APP-E013', name:'api-gateway',                  desc:'Enterprise API gateway: routing, rate limiting, auth, observability',      type:AssetType.API,             env:Environment.PRODUCTION,     dept:'Digital Products', crit:'Critical', cls:'Internet Facing', oe:'tarun.ahuja@msil.in',    net:true,  pii:false, bia:true,  url:'https://api-gw.msil.in',                                         vs:'Scheduled', nv:new Date('2026-07-01') },
    { appId:'APP-E014', name:'kyc-service',                  desc:'e-VKYC, Aadhaar verification, and CKYC registry integration API',          type:AssetType.API,             env:Environment.PRE_PRODUCTION, dept:'Digital Products', crit:'High',     cls:'Internet Facing', oe:'radha.k@msil.in',        net:true,  pii:true,  bia:true,  url:'https://kyc-uat.msil.in',                                        vs:'Scheduled', nv:new Date('2026-09-15') },
    // Modern Microservices (4)
    { appId:'APP-E015', name:'fraud-detection-engine',       desc:'Real-time ML fraud detection and transaction anomaly monitoring',          type:AssetType.MICROSERVICE,    env:Environment.PRODUCTION,     dept:'Core Banking',     crit:'Critical', cls:'Internal',        oe:'neha.agarwal@msil.in',   net:false, pii:true,  bia:true,                                                                vs:'Due',       nv:new Date('2026-07-30') },
    { appId:'APP-E016', name:'authentication-service',       desc:'Centralized auth microservice: JWT issuance, session, token refresh',     type:AssetType.MICROSERVICE,    env:Environment.PRODUCTION,     dept:'Digital Products', crit:'Critical', cls:'Internet Facing', oe:'tarun.ahuja@msil.in',    net:true,  pii:false, bia:true,                                                                vs:'Overdue',   nv:new Date('2026-06-15') },
    { appId:'APP-E017', name:'notification-service',         desc:'Multi-channel notification engine: SMS, email, push, in-app alerts',       type:AssetType.MICROSERVICE,    env:Environment.DEVELOPMENT,    dept:'Digital Products', crit:'Medium',   cls:'Internal',        oe:'ravi.joshi@msil.in',     net:false, pii:false, bia:false,                                                                vs:'Scheduled', nv:new Date('2026-10-01') },
    { appId:'APP-E018', name:'document-management-service',  desc:'Enterprise document repository microservice',                              type:AssetType.MICROSERVICE,    env:Environment.DEVELOPMENT,    dept:'Corporate IT',     crit:'Low',      cls:'Internal',        oe:'amit.kapoor@msil.in',    net:false, pii:false, bia:false,                                                                vs:'Scheduled', nv:new Date('2026-10-15') },
  ];

  const aMap: Record<string, string> = {};
  const appNow = new Date('2026-06-30T00:00:00Z');
  
    let appIdx = 0;
    for (const a of aDefs) {
      appIdx++;
      let lastVaptDate: Date | undefined;
      let nextVaptDate: Date | undefined;
      let vaptStatus: string | undefined;
  
      if (a.env === Environment.DEVELOPMENT) {
        // Dev apps rely on Shift-Left, no formal VAPT, but we populate lastVaptDate
        // with a recent internal security assessment date to ensure dashboard completeness.
        const daysAgo = (appIdx * 7 % 30) + 1;
      lastVaptDate = new Date(appNow.getTime() - daysAgo * 86400000);
      nextVaptDate = new Date(lastVaptDate.getTime() + 90 * 86400000);
      vaptStatus = 'Scheduled';
    } else {
      // Prod and Pre-Prod apps have VAPT
      // Deterministically assigned between 30 and 200 days ago
      const daysAgo = (appIdx * 19 % 170) + 30;
      lastVaptDate = new Date(appNow.getTime() - daysAgo * 86400000);
      
      // Critical apps = 180 day frequency. Others = 365 day frequency.
      const frequency = a.crit === 'Critical' ? 180 : 365;
      nextVaptDate = new Date(lastVaptDate.getTime() + frequency * 86400000);
      
      if (nextVaptDate < appNow) {
         vaptStatus = 'Overdue';
      } else if (nextVaptDate.getTime() - appNow.getTime() < 30 * 86400000) {
         vaptStatus = 'Due';
      } else {
         vaptStatus = 'Scheduled';
      }
    }

    const r = await prisma.application.upsert({
      where:  { appId: a.appId },
      update: { 
        name:a.name, description:a.desc, type:a.type, environment:a.env, department:a.dept, 
        criticality:a.crit, classification:a.cls, ownerId:uid(a.oe), ownerEmail:a.oe, 
        internetAccessible:a.net, piiData:a.pii, biaApp:a.bia, prodUrl:a.url, preprodUrl:a.pre, 
        vaptStatus:vaptStatus, lastVaptDate:lastVaptDate, nextVaptDate:nextVaptDate 
      },
      create: { 
        appId:a.appId, name:a.name, description:a.desc, type:a.type, environment:a.env, department:a.dept, 
        criticality:a.crit, classification:a.cls, ownerId:uid(a.oe), ownerEmail:a.oe, 
        internetAccessible:a.net, piiData:a.pii, biaApp:a.bia, prodUrl:a.url, preprodUrl:a.pre, 
        vaptStatus:vaptStatus, lastVaptDate:lastVaptDate, nextVaptDate:nextVaptDate, 
        isActive:true, registeredOn:new Date('2023-01-01') 
      },
    });
    aMap[a.appId] = r.id;
  }
  console.log(`✅ Applications (${aDefs.length})`);

  // ── 3. INFRASTRUCTURE ASSETS (60) ─────────────────────────────────────────
  type ID = { sid:string; sn:string; type:InfraType; env:Environment; ip:string; os:string; oe:string; loc:string; role:string; crit:string };
  const iDefs: ID[] = [
    // PRODUCTION APP SERVERS (10)
    { sid:'SRV-E001', sn:'prod-banking-app-01', type:InfraType.VIRTUAL_MACHINE,    env:Environment.PRODUCTION,     ip:'10.0.1.10', os:'RHEL 9.2',           oe:'narayan.iyengar@msil.in', loc:'AWS ap-south-1',       role:'Core Banking Portal app server (primary)',          crit:'Critical' },
    { sid:'SRV-E002', sn:'prod-banking-app-02', type:InfraType.VIRTUAL_MACHINE,    env:Environment.PRODUCTION,     ip:'10.0.1.11', os:'RHEL 9.2',           oe:'narayan.iyengar@msil.in', loc:'AWS ap-south-1',       role:'Core Banking Portal app server (secondary)',        crit:'Critical' },
    { sid:'SRV-E003', sn:'prod-erp-app-01',     type:InfraType.VIRTUAL_MACHINE,    env:Environment.PRODUCTION,     ip:'10.0.1.20', os:'Windows Server 2022',oe:'sudha.venkat@msil.in',    loc:'On-Premise DC-Mumbai', role:'Legacy ERP application server',                     crit:'High'     },
    { sid:'SRV-E004', sn:'prod-payment-app-01', type:InfraType.VIRTUAL_MACHINE,    env:Environment.PRODUCTION,     ip:'10.0.1.30', os:'RHEL 9.2',           oe:'narayan.iyengar@msil.in', loc:'AWS ap-south-1',       role:'Payment Switch application node',                   crit:'Critical' },
    { sid:'SRV-E005', sn:'prod-trade-app-01',   type:InfraType.VIRTUAL_MACHINE,    env:Environment.PRODUCTION,     ip:'10.0.1.40', os:'Ubuntu 22.04 LTS',   oe:'sudha.venkat@msil.in',    loc:'AWS ap-south-1',       role:'Trade Finance Portal app server',                   crit:'High'     },
    { sid:'SRV-E006', sn:'prod-c360-app-01',    type:InfraType.VIRTUAL_MACHINE,    env:Environment.PRODUCTION,     ip:'10.0.1.50', os:'Ubuntu 22.04 LTS',   oe:'narayan.iyengar@msil.in', loc:'Azure East India',     role:'Customer 360 Portal node',                          crit:'High'     },
    { sid:'SRV-E007', sn:'prod-hrms-app-01',    type:InfraType.VIRTUAL_MACHINE,    env:Environment.PRODUCTION,     ip:'10.0.1.60', os:'Windows Server 2022',oe:'sudha.venkat@msil.in',    loc:'AWS ap-south-1',       role:'HRMS application node',                             crit:'Medium'   },
    { sid:'SRV-E008', sn:'prod-dealer-app-01',  type:InfraType.VIRTUAL_MACHINE,    env:Environment.PRODUCTION,     ip:'10.0.1.70', os:'Ubuntu 22.04 LTS',   oe:'narayan.iyengar@msil.in', loc:'Azure East India',     role:'Dealer Management Portal server',                   crit:'Medium'   },
    { sid:'SRV-E009', sn:'prod-intra-app-01',   type:InfraType.VIRTUAL_MACHINE,    env:Environment.PRODUCTION,     ip:'10.0.1.80', os:'Ubuntu 22.04 LTS',   oe:'sudha.venkat@msil.in',    loc:'AWS ap-south-1',       role:'Corporate Intranet application server',             crit:'Low'      },
    { sid:'SRV-E010', sn:'prod-comp-app-01',    type:InfraType.VIRTUAL_MACHINE,    env:Environment.PRODUCTION,     ip:'10.0.1.90', os:'Ubuntu 22.04 LTS',   oe:'narayan.iyengar@msil.in', loc:'AWS ap-south-1',       role:'Compliance Portal node',                            crit:'High'     },
    // DATABASE SERVERS (6)
    { sid:'SRV-E011', sn:'prod-banking-db-01',  type:InfraType.DATABASE_SERVER,    env:Environment.PRODUCTION,     ip:'10.0.2.10', os:'Oracle 19c',         oe:'usha.bala@msil.in',       loc:'On-Premise DC-Mumbai', role:'Core banking primary DB',                           crit:'Critical' },
    { sid:'SRV-E012', sn:'prod-erp-db-01',      type:InfraType.DATABASE_SERVER,    env:Environment.PRODUCTION,     ip:'10.0.2.20', os:'MS SQL Server 2019', oe:'usha.bala@msil.in',       loc:'On-Premise DC-Mumbai', role:'Legacy ERP DB',                                     crit:'High'     },
    { sid:'SRV-E013', sn:'prod-c360-db-01',     type:InfraType.DATABASE_SERVER,    env:Environment.PRODUCTION,     ip:'10.0.2.30', os:'PostgreSQL 15',      oe:'usha.bala@msil.in',       loc:'Azure East India',     role:'Customer 360 DB',                                   crit:'High'     },
    { sid:'SRV-E014', sn:'prod-hrms-db-01',     type:InfraType.DATABASE_SERVER,    env:Environment.PRODUCTION,     ip:'10.0.2.40', os:'MySQL 8',            oe:'usha.bala@msil.in',       loc:'AWS ap-south-1',       role:'HRMS Database',                                     crit:'Medium'   },
    { sid:'SRV-E015', sn:'prod-comp-db-01',     type:InfraType.DATABASE_SERVER,    env:Environment.PRODUCTION,     ip:'10.0.2.50', os:'PostgreSQL 15',      oe:'usha.bala@msil.in',       loc:'AWS ap-south-1',       role:'Compliance Portal DB',                              crit:'High'     },
    { sid:'SRV-E016', sn:'prod-dealer-db-01',   type:InfraType.DATABASE_SERVER,    env:Environment.PRODUCTION,     ip:'10.0.2.60', os:'PostgreSQL 15',      oe:'usha.bala@msil.in',       loc:'Azure East India',     role:'Dealer Management DB',                              crit:'Medium'   },
    // KUBERNETES CLUSTERS (4)
    { sid:'SRV-E017', sn:'prod-k8s-api-01',     type:InfraType.CONTAINER_CLUSTER,  env:Environment.PRODUCTION,     ip:'10.0.3.10', os:'EKS 1.29',           oe:'kiran.dev@msil.in',       loc:'AWS ap-south-1',       role:'Public APIs Container Cluster',                     crit:'Critical' },
    { sid:'SRV-E018', sn:'prod-k8s-micro-01',   type:InfraType.CONTAINER_CLUSTER,  env:Environment.PRODUCTION,     ip:'10.0.3.20', os:'AKS 1.28',           oe:'kiran.dev@msil.in',       loc:'Azure East India',     role:'Modern Microservices Cluster',                      crit:'Critical' },
    { sid:'SRV-E019', sn:'preprod-k8s-api-01',  type:InfraType.CONTAINER_CLUSTER,  env:Environment.PRE_PRODUCTION, ip:'10.1.3.10', os:'EKS 1.29',           oe:'kiran.dev@msil.in',       loc:'AWS ap-south-1',       role:'Pre-production API cluster',                        crit:'High'     },
    { sid:'SRV-E020', sn:'dev-k8s-micro-01',    type:InfraType.CONTAINER_CLUSTER,  env:Environment.DEVELOPMENT,    ip:'10.2.3.10', os:'AKS 1.28',           oe:'kiran.dev@msil.in',       loc:'Azure East India',     role:'Development Microservices Cluster',                 crit:'Medium'   },
    // FIREWALLS (4)
    { sid:'SRV-E021', sn:'fw-prod-perimeter-01',type:InfraType.FIREWALL,           env:Environment.PRODUCTION,     ip:'203.0.113.1',os:'FortiOS 7.4',        oe:'vijay.mehta@msil.in',     loc:'AWS ap-south-1',       role:'Perimeter firewall — internet-facing DMZ',         crit:'Critical' },
    { sid:'SRV-E022', sn:'fw-prod-internal-01', type:InfraType.FIREWALL,           env:Environment.PRODUCTION,     ip:'10.0.0.1',  os:'Palo Alto PAN-OS 11',oe:'vijay.mehta@msil.in',     loc:'On-Premise DC-Mumbai', role:'Internal segmentation firewall (legacy core)',      crit:'Critical' },
    { sid:'SRV-E023', sn:'fw-azure-01',         type:InfraType.FIREWALL,           env:Environment.PRODUCTION,     ip:'10.10.0.1', os:'Azure Firewall',      oe:'vijay.mehta@msil.in',     loc:'Azure East India',     role:'Azure perimeter firewall',                          crit:'High'     },
    { sid:'SRV-E024', sn:'fw-preprod-01',       type:InfraType.FIREWALL,           env:Environment.PRE_PRODUCTION, ip:'10.1.0.1',  os:'FortiOS 7.4',         oe:'vijay.mehta@msil.in',     loc:'AWS ap-south-1',       role:'Pre-production environment firewall',               crit:'Medium'   },
    // NETWORK DEVICES (3)
    { sid:'SRV-E025', sn:'sw-prod-core-01',     type:InfraType.NETWORK_DEVICE,     env:Environment.PRODUCTION,     ip:'10.0.0.10', os:'Cisco IOS XE 17.9',  oe:'manoj.pillai@msil.in',    loc:'On-Premise DC-Mumbai', role:'Core network switch — Mumbai DC spine',            crit:'Critical' },
    { sid:'SRV-E026', sn:'router-prod-edge-01', type:InfraType.NETWORK_DEVICE,     env:Environment.PRODUCTION,     ip:'10.0.0.30', os:'Cisco IOS XR 7.9',   oe:'manoj.pillai@msil.in',    loc:'On-Premise DC-Mumbai', role:'Edge router — ISP peering (primary)',               crit:'Critical' },
    { sid:'SRV-E027', sn:'router-azure-01',     type:InfraType.NETWORK_DEVICE,     env:Environment.PRODUCTION,     ip:'10.10.0.10',os:'Azure VPN Gateway',   oe:'manoj.pillai@msil.in',    loc:'Azure East India',     role:'Azure VPN Gateway — on-prem connectivity',        crit:'High'     },
    // PRE-PRODUCTION APP SERVERS (3)
    { sid:'SRV-E028', sn:'preprod-banking-01',  type:InfraType.VIRTUAL_MACHINE,    env:Environment.PRE_PRODUCTION, ip:'10.1.1.10', os:'RHEL 9.2',           oe:'narayan.iyengar@msil.in', loc:'AWS ap-south-1',       role:'Pre-production banking app server',                 crit:'High'     },
    { sid:'SRV-E029', sn:'preprod-erp-01',      type:InfraType.VIRTUAL_MACHINE,    env:Environment.PRE_PRODUCTION, ip:'10.1.1.20', os:'Windows Server 2022',oe:'sudha.venkat@msil.in',    loc:'On-Premise DC-Mumbai', role:'Pre-production ERP app server',                     crit:'High'     },
    { sid:'SRV-E030', sn:'preprod-db-01',       type:InfraType.DATABASE_SERVER,    env:Environment.PRE_PRODUCTION, ip:'10.1.2.10', os:'Oracle 19c',         oe:'usha.bala@msil.in',       loc:'On-Premise DC-Mumbai', role:'Pre-production shared DB',                          crit:'High'     }
  ];

  const iMap: Record<string, string> = {};
  for (const i of iDefs) {
    const r = await prisma.infrastructureAsset.upsert({
      where:  { serverId: i.sid },
      update: { serverName:i.sn, type:i.type, environment:i.env, ip:i.ip, os:i.os, assetOwnerId:uid(i.oe), assetOwnerEmail:i.oe, location:i.loc, role:i.role, criticality:i.crit },
      create: { serverId:i.sid, serverName:i.sn, type:i.type, environment:i.env, ip:i.ip, os:i.os, assetOwnerId:uid(i.oe), assetOwnerEmail:i.oe, location:i.loc, role:i.role, criticality:i.crit, isActive:true },
    });
    iMap[i.sid] = r.id;
  }
  console.log(`✅ Infrastructure Assets (${iDefs.length})`);

  // ── 4. CLOUD ACCOUNTS (8) ─────────────────────────────────────────────────
  type CA = { aid:string; extId:string; provider:CloudProvider; env:Environment; label:string };
  const caDefs: CA[] = [
    { aid:'CA-E001', extId:'111122223333', provider:CloudProvider.AWS,   env:Environment.PRODUCTION,     label:'AWS Production — ap-south-1 primary workloads' },
    { aid:'CA-E002', extId:'444455556666', provider:CloudProvider.AWS,   env:Environment.PRE_PRODUCTION, label:'AWS Non-Production — UAT and staging environments' },
    { aid:'CA-E003', extId:'777788889999', provider:CloudProvider.AWS,   env:Environment.PRODUCTION,     label:'AWS Security — GuardDuty, Security Hub, CloudTrail' },
    { aid:'CA-E004', extId:'aabb11223344', provider:CloudProvider.AZURE, env:Environment.PRODUCTION,     label:'Azure Production — East India (IAM and enterprise apps)' },
    { aid:'CA-E005', extId:'ccdd55667788', provider:CloudProvider.AZURE, env:Environment.PRODUCTION,     label:'Azure Disaster Recovery — South India' },
    { aid:'CA-E006', extId:'eeff99001122', provider:CloudProvider.AZURE, env:Environment.PRODUCTION,     label:'Azure Identity — Entra ID and Active Directory Federation' },
    { aid:'CA-E007', extId:'gggg12345678', provider:CloudProvider.GCP,   env:Environment.PRODUCTION,     label:'GCP Analytics — BigQuery, Dataflow, Looker dashboards' },
    { aid:'CA-E008', extId:'hhhh87654321', provider:CloudProvider.GCP,   env:Environment.PRODUCTION,     label:'GCP Shared Services — Container Registry and Artifact' },
    { aid:'CA-E009', extId:'101020203030', provider:CloudProvider.AWS,   env:Environment.DEVELOPMENT,    label:'AWS Development — Ephemeral workloads and sandboxes' },
  ];

  const caMap: Record<string, string> = {};
  for (const ca of caDefs) {
    const r = await prisma.cloudAccount.upsert({
      where:  { accountId: ca.aid },
      update: { extId:ca.extId, provider:ca.provider, environment:ca.env, label:ca.label },
      create: { accountId:ca.aid, extId:ca.extId, provider:ca.provider, environment:ca.env, label:ca.label },
    });
    caMap[ca.aid] = r.id;
  }
  console.log(`✅ Cloud Accounts (${caDefs.length})`);

  // ── 5. CLOUD RESOURCES (30) ─────────────────────────────────────────────────
  type CR = { cid:string; name:string; extId?:string; type:CloudResourceType; tech:string; stack:string; provider:CloudProvider; aid:string; status:string; region:string; env:Environment; fs:Date };
  const crDefs: CR[] = [
    // AWS PROD (CA-E001)
    { cid:'CR-E001', name:'aws-prod-eks-01', extId:'eks-prod-mumbai-01', type:CloudResourceType.CONTAINER, tech:'Amazon EKS', stack:'Platform', provider:CloudProvider.AWS, aid:'CA-E001', status:'Active', region:'ap-south-1', env:Environment.PRODUCTION, fs:new Date('2024-01-10') },
    { cid:'CR-E002', name:'aws-prod-rds-banking', extId:'db-abc123xyz', type:CloudResourceType.DATABASE, tech:'Amazon RDS Oracle', stack:'Data', provider:CloudProvider.AWS, aid:'CA-E001', status:'Available', region:'ap-south-1', env:Environment.PRODUCTION, fs:new Date('2024-01-15') },
    { cid:'CR-E003', name:'aws-prod-alb-banking', type:CloudResourceType.NETWORK, tech:'AWS ALB', stack:'Infrastructure', provider:CloudProvider.AWS, aid:'CA-E001', status:'Active', region:'ap-south-1', env:Environment.PRODUCTION, fs:new Date('2024-01-20') },
    { cid:'CR-E004', name:'aws-prod-vpc-core', type:CloudResourceType.NETWORK, tech:'Amazon VPC', stack:'Infrastructure', provider:CloudProvider.AWS, aid:'CA-E001', status:'Available', region:'ap-south-1', env:Environment.PRODUCTION, fs:new Date('2024-01-05') },
    { cid:'CR-E005', name:'aws-prod-s3-docs', type:CloudResourceType.STORAGE, tech:'Amazon S3', stack:'Data', provider:CloudProvider.AWS, aid:'CA-E001', status:'Active', region:'ap-south-1', env:Environment.PRODUCTION, fs:new Date('2024-02-01') },
    { cid:'CR-E006', name:'aws-prod-ec2-bastion', extId:'i-0a1b2c3d4e5f6', type:CloudResourceType.COMPUTE, tech:'Amazon EC2', stack:'Infrastructure', provider:CloudProvider.AWS, aid:'CA-E001', status:'Running', region:'ap-south-1', env:Environment.PRODUCTION, fs:new Date('2024-02-15') },
    { cid:'CR-E007', name:'aws-prod-ec2-app01', extId:'i-0b2c3d4e5f6a7', type:CloudResourceType.COMPUTE, tech:'Amazon EC2', stack:'Infrastructure', provider:CloudProvider.AWS, aid:'CA-E001', status:'Running', region:'ap-south-1', env:Environment.PRODUCTION, fs:new Date('2024-02-15') },
    { cid:'CR-E008', name:'aws-prod-rds-payments', extId:'db-def456uvw', type:CloudResourceType.DATABASE, tech:'Amazon RDS PostgreSQL', stack:'Data', provider:CloudProvider.AWS, aid:'CA-E001', status:'Available', region:'ap-south-1', env:Environment.PRODUCTION, fs:new Date('2024-03-01') },
    { cid:'CR-E009', name:'aws-prod-dynamodb', type:CloudResourceType.DATABASE, tech:'Amazon DynamoDB', stack:'Data', provider:CloudProvider.AWS, aid:'CA-E001', status:'Active', region:'ap-south-1', env:Environment.PRODUCTION, fs:new Date('2024-03-22') },
    { cid:'CR-E010', name:'aws-prod-elasticache', type:CloudResourceType.DATABASE, tech:'Amazon ElastiCache', stack:'Data', provider:CloudProvider.AWS, aid:'CA-E001', status:'Available', region:'ap-south-1', env:Environment.PRODUCTION, fs:new Date('2024-04-01') },
    // AZURE PROD (CA-E004)
    { cid:'CR-E011', name:'azure-prod-aks-01', type:CloudResourceType.CONTAINER, tech:'Azure Kubernetes Service', stack:'Platform', provider:CloudProvider.AZURE, aid:'CA-E004', status:'Running', region:'Central India', env:Environment.PRODUCTION, fs:new Date('2024-02-05') },
    { cid:'CR-E012', name:'azure-prod-sql-crm', type:CloudResourceType.DATABASE, tech:'Azure SQL Database', stack:'Data', provider:CloudProvider.AZURE, aid:'CA-E004', status:'Online', region:'Central India', env:Environment.PRODUCTION, fs:new Date('2024-02-10') },
    { cid:'CR-E013', name:'azure-prod-vnet-01', type:CloudResourceType.NETWORK, tech:'Azure Virtual Network', stack:'Infrastructure', provider:CloudProvider.AZURE, aid:'CA-E004', status:'Active', region:'Central India', env:Environment.PRODUCTION, fs:new Date('2024-02-01') },
    { cid:'CR-E014', name:'azure-prod-appgw-01', type:CloudResourceType.NETWORK, tech:'Azure Application Gateway', stack:'Infrastructure', provider:CloudProvider.AZURE, aid:'CA-E004', status:'Running', region:'Central India', env:Environment.PRODUCTION, fs:new Date('2024-02-15') },
    { cid:'CR-E015', name:'azure-prod-storage-docs', type:CloudResourceType.STORAGE, tech:'Azure Blob Storage', stack:'Data', provider:CloudProvider.AZURE, aid:'CA-E004', status:'Available', region:'Central India', env:Environment.PRODUCTION, fs:new Date('2024-02-20') },
    { cid:'CR-E016', name:'azure-prod-vm-app1', type:CloudResourceType.COMPUTE, tech:'Azure Virtual Machines', stack:'Infrastructure', provider:CloudProvider.AZURE, aid:'CA-E004', status:'Running', region:'Central India', env:Environment.PRODUCTION, fs:new Date('2024-03-01') },
    { cid:'CR-E017', name:'azure-prod-cosmosdb', type:CloudResourceType.DATABASE, tech:'Azure Cosmos DB', stack:'Data', provider:CloudProvider.AZURE, aid:'CA-E004', status:'Online', region:'Central India', env:Environment.PRODUCTION, fs:new Date('2024-03-10') },
    { cid:'CR-E018', name:'azure-prod-func-sync', type:CloudResourceType.SERVERLESS, tech:'Azure Functions', stack:'Platform', provider:CloudProvider.AZURE, aid:'CA-E004', status:'Running', region:'Central India', env:Environment.PRODUCTION, fs:new Date('2024-03-15') },
    { cid:'CR-E019', name:'azure-prod-eventhub', type:CloudResourceType.NETWORK, tech:'Azure Event Hubs', stack:'Platform', provider:CloudProvider.AZURE, aid:'CA-E004', status:'Active', region:'Central India', env:Environment.PRODUCTION, fs:new Date('2024-03-20') },
    { cid:'CR-E020', name:'azure-prod-keyvault', type:CloudResourceType.SECURITY, tech:'Azure Key Vault', stack:'Security', provider:CloudProvider.AZURE, aid:'CA-E004', status:'Active', region:'Central India', env:Environment.PRODUCTION, fs:new Date('2024-02-12') },
    // GCP PROD (CA-E007)
    { cid:'CR-E021', name:'gcp-prod-bigquery-dwh', type:CloudResourceType.DATABASE, tech:'Google BigQuery', stack:'Data', provider:CloudProvider.GCP, aid:'CA-E007', status:'Active', region:'asia-south1', env:Environment.PRODUCTION, fs:new Date('2024-04-01') },
    { cid:'CR-E022', name:'gcp-prod-dataflow', type:CloudResourceType.OTHER, tech:'Google Cloud Dataflow', stack:'Data', provider:CloudProvider.GCP, aid:'CA-E007', status:'Running', region:'asia-south1', env:Environment.PRODUCTION, fs:new Date('2024-04-05') },
    { cid:'CR-E023', name:'gcp-prod-dataproc', type:CloudResourceType.COMPUTE, tech:'Google Cloud Dataproc', stack:'Data', provider:CloudProvider.GCP, aid:'CA-E007', status:'Running', region:'asia-south1', env:Environment.PRODUCTION, fs:new Date('2024-04-10') },
    { cid:'CR-E024', name:'gcp-prod-pubsub', type:CloudResourceType.NETWORK, tech:'Google Cloud Pub/Sub', stack:'Platform', provider:CloudProvider.GCP, aid:'CA-E007', status:'Active', region:'asia-south1', env:Environment.PRODUCTION, fs:new Date('2024-04-15') },
    { cid:'CR-E025', name:'gcp-prod-gcs-lake', type:CloudResourceType.STORAGE, tech:'Google Cloud Storage', stack:'Data', provider:CloudProvider.GCP, aid:'CA-E007', status:'Active', region:'asia-south1', env:Environment.PRODUCTION, fs:new Date('2024-04-20') },
    // PREPROD & SECURITY
    { cid:'CR-E026', name:'aws-sec-guardduty', type:CloudResourceType.SECURITY, tech:'Amazon GuardDuty', stack:'Security', provider:CloudProvider.AWS, aid:'CA-E003', status:'Enabled', region:'ap-south-1', env:Environment.PRODUCTION, fs:new Date('2024-01-20') },
    { cid:'CR-E027', name:'aws-sec-cloudtrail', type:CloudResourceType.STORAGE, tech:'Amazon S3', stack:'Data', provider:CloudProvider.AWS, aid:'CA-E003', status:'Active', region:'ap-south-1', env:Environment.PRODUCTION, fs:new Date('2024-01-15') },
    { cid:'CR-E028', name:'aws-preprod-eks', type:CloudResourceType.CONTAINER, tech:'Amazon EKS', stack:'Platform', provider:CloudProvider.AWS, aid:'CA-E002', status:'Active', region:'ap-south-1', env:Environment.PRE_PRODUCTION, fs:new Date('2024-06-01') },
    { cid:'CR-E029', name:'aws-preprod-rds', type:CloudResourceType.DATABASE, tech:'Amazon RDS PostgreSQL', stack:'Data', provider:CloudProvider.AWS, aid:'CA-E002', status:'Available', region:'ap-south-1', env:Environment.PRE_PRODUCTION, fs:new Date('2024-06-05') },
    { cid:'CR-E030', name:'aws-preprod-vpc', type:CloudResourceType.NETWORK, tech:'Amazon VPC', stack:'Infrastructure', provider:CloudProvider.AWS, aid:'CA-E002', status:'Available', region:'ap-south-1', env:Environment.PRE_PRODUCTION, fs:new Date('2024-05-15') }
  ];

  const crMap: Record<string, string> = {};
  for (const cr of crDefs) {
    const accountId = caMap[cr.aid];
    if (!accountId) {
      console.warn(`⚠️ Cloud Account missing for ${cr.cid}`);
      continue;
    }
    const r = await prisma.cloudResource.upsert({
      where:  { resourceId: cr.cid },
      update: { resourceName:cr.name, resourceExtId:cr.extId, type:cr.type, technologyName:cr.tech, stackLayer:cr.stack, cloudProvider:cr.provider, cloudAccountId:accountId, status:cr.status, region:cr.region, environment:cr.env },
      create: { resourceId:cr.cid, resourceName:cr.name, resourceExtId:cr.extId, type:cr.type, technologyName:cr.tech, stackLayer:cr.stack, cloudProvider:cr.provider, cloudAccountId:accountId, status:cr.status, region:cr.region, environment:cr.env, firstSeen:cr.fs },
    });
    crMap[cr.cid] = r.id;
  }
  console.log(`✅ Cloud Resources (${crDefs.length})`);

  // ── 6. APPLICATION ↔ INFRASTRUCTURE (Wave 1.6A) ───────────────────────────
  const appInfraMap: Array<{ a: string; i: string }> = [
    { a: 'APP-E001', i: 'SRV-E001' }, { a: 'APP-E001', i: 'SRV-E002' }, { a: 'APP-E001', i: 'SRV-E011' }, { a: 'APP-E001', i: 'SRV-E025' },
    { a: 'APP-E002', i: 'SRV-E003' }, { a: 'APP-E002', i: 'SRV-E012' }, { a: 'APP-E002', i: 'SRV-E022' }, { a: 'APP-E002', i: 'SRV-E029' },
    { a: 'APP-E003', i: 'SRV-E004' }, { a: 'APP-E003', i: 'SRV-E011' }, { a: 'APP-E003', i: 'SRV-E022' },
    { a: 'APP-E004', i: 'SRV-E001' }, { a: 'APP-E004', i: 'SRV-E021' }, { a: 'APP-E004', i: 'SRV-E026' },
    { a: 'APP-E005', i: 'SRV-E005' }, { a: 'APP-E005', i: 'SRV-E021' },
    { a: 'APP-E006', i: 'SRV-E006' }, { a: 'APP-E006', i: 'SRV-E013' }, { a: 'APP-E006', i: 'SRV-E023' },
    { a: 'APP-E007', i: 'SRV-E008' }, { a: 'APP-E007', i: 'SRV-E016' }, { a: 'APP-E007', i: 'SRV-E023' },
    { a: 'APP-E008', i: 'SRV-E028' }, { a: 'APP-E008', i: 'SRV-E030' }, { a: 'APP-E008', i: 'SRV-E024' },
    { a: 'APP-E009', i: 'SRV-E007' }, { a: 'APP-E009', i: 'SRV-E014' },
    { a: 'APP-E010', i: 'SRV-E009' }, { a: 'APP-E010', i: 'SRV-E021' },
    { a: 'APP-E011', i: 'SRV-E010' }, { a: 'APP-E011', i: 'SRV-E015' }, { a: 'APP-E011', i: 'SRV-E021' },
    { a: 'APP-E012', i: 'SRV-E017' }, { a: 'APP-E012', i: 'SRV-E011' }, { a: 'APP-E012', i: 'SRV-E026' },
    { a: 'APP-E013', i: 'SRV-E017' }, { a: 'APP-E013', i: 'SRV-E021' }, { a: 'APP-E013', i: 'SRV-E026' },
    { a: 'APP-E014', i: 'SRV-E019' }, { a: 'APP-E014', i: 'SRV-E024' },
    { a: 'APP-E015', i: 'SRV-E018' }, { a: 'APP-E015', i: 'SRV-E011' }, { a: 'APP-E015', i: 'SRV-E022' },
    { a: 'APP-E016', i: 'SRV-E018' }, { a: 'APP-E016', i: 'SRV-E013' }, { a: 'APP-E016', i: 'SRV-E027' },
    { a: 'APP-E017', i: 'SRV-E020' },
    { a: 'APP-E018', i: 'SRV-E020' },
  ];

  const appInfraRecords = appInfraMap.map(mapping => ({
    applicationId: aMap[mapping.a],
    infrastructureAssetId: iMap[mapping.i],
  })).filter(r => r.applicationId && r.infrastructureAssetId);

  await prisma.appInfrastructureAsset.createMany({
    data: appInfraRecords,
    skipDuplicates: true,
  });
  console.log(`✅ Application ↔ Infrastructure Links (${appInfraRecords.length})`);

  // ── 7. APPLICATION ↔ CLOUD RESOURCE (Wave 1.6B) ───────────────────────────
  const appCloudMap: Array<{ a: string; c: string }> = [
    { a: 'APP-E001', c: 'CR-E001' }, { a: 'APP-E001', c: 'CR-E002' }, { a: 'APP-E001', c: 'CR-E003' }, { a: 'APP-E001', c: 'CR-E004' },
    { a: 'APP-E002', c: 'CR-E001' }, { a: 'APP-E002', c: 'CR-E004' }, { a: 'APP-E002', c: 'CR-E011' }, { a: 'APP-E002', c: 'CR-E012' },
    { a: 'APP-E003', c: 'CR-E010' }, { a: 'APP-E003', c: 'CR-E009' }, { a: 'APP-E003', c: 'CR-E013' },
    { a: 'APP-E004', c: 'CR-E007' }, { a: 'APP-E004', c: 'CR-E008' }, { a: 'APP-E004', c: 'CR-E014' },
    { a: 'APP-E005', c: 'CR-E021' }, { a: 'APP-E005', c: 'CR-E022' }, { a: 'APP-E005', c: 'CR-E015' },
    { a: 'APP-E006', c: 'CR-E017' }, { a: 'APP-E006', c: 'CR-E018' }, { a: 'APP-E006', c: 'CR-E019' },
    { a: 'APP-E007', c: 'CR-E017' }, { a: 'APP-E007', c: 'CR-E018' }, { a: 'APP-E007', c: 'CR-E019' },
    { a: 'APP-E008', c: 'CR-E001' }, { a: 'APP-E008', c: 'CR-E016' }, { a: 'APP-E008', c: 'CR-E020' },
    { a: 'APP-E009', c: 'CR-E011' }, { a: 'APP-E009', c: 'CR-E021' },
    { a: 'APP-E010', c: 'CR-E011' }, { a: 'APP-E010', c: 'CR-E012' },
    { a: 'APP-E011', c: 'CR-E026' }, { a: 'APP-E011', c: 'CR-E027' },
    { a: 'APP-E012', c: 'CR-E003' }, { a: 'APP-E012', c: 'CR-E018' }, { a: 'APP-E012', c: 'CR-E017' },
    { a: 'APP-E013', c: 'CR-E011' }, { a: 'APP-E013', c: 'CR-E012' }, { a: 'APP-E013', c: 'CR-E013' },
    { a: 'APP-E014', c: 'CR-E016' }, { a: 'APP-E014', c: 'CR-E013' },
    { a: 'APP-E015', c: 'CR-E015' }, { a: 'APP-E015', c: 'CR-E016' },
    { a: 'APP-E016', c: 'CR-E017' }, { a: 'APP-E016', c: 'CR-E018' },
    { a: 'APP-E017', c: 'CR-E017' }, { a: 'APP-E017', c: 'CR-E013' },
    { a: 'APP-E018', c: 'CR-E011' }, { a: 'APP-E018', c: 'CR-E022' }, { a: 'APP-E018', c: 'CR-E020' },
  ];

  const appCloudRecords = appCloudMap.map(mapping => ({
    applicationId: aMap[mapping.a],
    cloudResourceId: crMap[mapping.c],
  })).filter(r => r.applicationId && r.cloudResourceId);

  await prisma.appCloudResource.createMany({
    data: appCloudRecords,
    skipDuplicates: true,
  });
  console.log(`✅ Application ↔ Cloud Resource Links (${appCloudRecords.length})`);

  console.log('✅ Wave 1 — Enterprise Foundation complete.');

  // =============================================================================
  // WAVE 2: SECURITY OPERATIONS HISTORY
  // =============================================================================
  
  // ── 8. TIMELINE FOUNDATION (Wave 2.1) ───────────────────────────────────────
  // A 12-month calendar (July 2025 – June 2026) to drive realistic data generation.
  // Note: No requests are generated in this wave. This is purely the architectural 
  // timeline and distribution strategy for future waves.

  enum OpIntensity { LOW = 'LOW', NORMAL = 'NORMAL', HIGH = 'HIGH', PEAK = 'PEAK' }

  type MonthlyProfile = {
    monthStr: string; // e.g., '2025-07'
    intensity: OpIntensity;
    theme: string;
    vaptWeight: number; // relative weighting for randomly spreading ~150 total requests
    bbWeight: number;
    rtWeight: number;
    csWeight: number;
  };

  const operationalCalendar: MonthlyProfile[] = [
    // Q1
    { monthStr: '2025-07', intensity: OpIntensity.NORMAL, theme: 'Quarterly VAPT Kickoff', vaptWeight: 3, bbWeight: 1, rtWeight: 0, csWeight: 2 },
    { monthStr: '2025-08', intensity: OpIntensity.HIGH, theme: 'Major Product Release', vaptWeight: 4, bbWeight: 2, rtWeight: 0, csWeight: 2 },
    { monthStr: '2025-09', intensity: OpIntensity.NORMAL, theme: 'Cloud Reviews', vaptWeight: 2, bbWeight: 1, rtWeight: 0, csWeight: 3 },
    // Q2
    { monthStr: '2025-10', intensity: OpIntensity.HIGH, theme: 'External Pen Tests', vaptWeight: 5, bbWeight: 1, rtWeight: 1, csWeight: 2 },
    { monthStr: '2025-11', intensity: OpIntensity.PEAK, theme: 'Major Patch Tuesday & Black Friday Prep', vaptWeight: 2, bbWeight: 4, rtWeight: 1, csWeight: 4 },
    { monthStr: '2025-12', intensity: OpIntensity.LOW, theme: 'Holiday Change Freeze', vaptWeight: 1, bbWeight: 1, rtWeight: 0, csWeight: 1 },
    // Q3
    { monthStr: '2026-01', intensity: OpIntensity.NORMAL, theme: 'New Year Baseline', vaptWeight: 2, bbWeight: 1, rtWeight: 0, csWeight: 2 },
    { monthStr: '2026-02', intensity: OpIntensity.HIGH, theme: 'Infrastructure Hardening', vaptWeight: 3, bbWeight: 1, rtWeight: 2, csWeight: 3 },
    { monthStr: '2026-03', intensity: OpIntensity.PEAK, theme: 'Bug Bounty Surge', vaptWeight: 2, bbWeight: 5, rtWeight: 1, csWeight: 2 },
    // Q4
    { monthStr: '2026-04', intensity: OpIntensity.HIGH, theme: 'Red Team Exercise', vaptWeight: 2, bbWeight: 1, rtWeight: 5, csWeight: 2 },
    { monthStr: '2026-05', intensity: OpIntensity.PEAK, theme: 'Annual Compliance Audit', vaptWeight: 6, bbWeight: 1, rtWeight: 0, csWeight: 2 },
    { monthStr: '2026-06', intensity: OpIntensity.LOW, theme: 'End-of-Year Freeze / Remediation Focus', vaptWeight: 1, bbWeight: 1, rtWeight: 0, csWeight: 1 },
  ];

  // Helper functions for timeline generation in Wave 2.x
  // @ts-ignore - Reserved for next wave
  let globalDateSeed = 1;
  const getRandomDateInMonth = (monthStr: string): Date => {
    const [yyyy, mm] = monthStr.split('-').map(Number);
    globalDateSeed++;
    const day = (globalDateSeed * 7 % 28) + 1;
    const date = new Date(yyyy, mm - 1, day);
    date.setHours(9 + (globalDateSeed % 8), (globalDateSeed * 13 % 60), 0);
    return date;
  };

  // @ts-ignore - Reserved for next wave
  const getCalendarProfile = (monthStr: string) => operationalCalendar.find(c => c.monthStr === monthStr);

  console.log(`📅 Wave 2.1 — Timeline foundation initialized (July 2025 to June 2026).`);

  // ── 9. SECURITY REQUESTS (Wave 2.2) ───────────────────────────────────────
  const secAnalysts = uDefs.filter(u => u.role === UserRole.SECURITY_ANALYST || u.role === UserRole.SECURITY_LEAD);
  
  const sources = [
    { type: 'VAPT', target: 28 },
    { type: 'BUG_BOUNTY', target: 18 },
    { type: 'CLOUDSEK', target: 14 },
    { type: 'RED_TEAM', target: 8 },
  ];

  const reqDefs: any[] = [];
  let reqCounter = 1;
  const now = new Date('2026-06-30T00:00:00Z');

  const appUsage: Record<string, number> = {};
  aDefs.forEach(a => appUsage[a.appId] = 0);
  const infraUsage: Record<string, number> = {};
  iDefs.forEach(i => infraUsage[i.sid] = 0);

  for (const src of sources) {
    for (let i = 0; i < src.target; i++) {
      // Pick month probabilistically
      const totalWeight = operationalCalendar.reduce((sum, c) => {
        if (src.type === 'VAPT') return sum + c.vaptWeight;
        if (src.type === 'BUG_BOUNTY') return sum + c.bbWeight;
        if (src.type === 'RED_TEAM') return sum + c.rtWeight;
        if (src.type === 'CLOUDSEK' || src.type === 'CVS') return sum + c.csWeight;
        return sum;
      }, 0);
      
      let rand = ((reqCounter * 17) % 100) / 100 * totalWeight;
      let selectedMonth = operationalCalendar[0];
      for (const cal of operationalCalendar) {
        const w = (src.type === 'VAPT') ? cal.vaptWeight :
                  (src.type === 'BUG_BOUNTY') ? cal.bbWeight :
                  (src.type === 'RED_TEAM') ? cal.rtWeight :
                  cal.csWeight;
        if (rand < w) { selectedMonth = cal; break; }
        rand -= w;
      }
      
      const initiatedOn = getRandomDateInMonth(selectedMonth.monthStr);
      const ageDays = (now.getTime() - initiatedOn.getTime()) / (1000 * 3600 * 24);
      
      // Target Entity
      let isApp = true;
      if (src.type === 'CVS') isApp = (reqCounter % 10) <= 8; 
      else if (src.type === 'VAPT') isApp = (reqCounter % 10) <= 2;
      else if (src.type === 'RED_TEAM') isApp = (reqCounter % 10) <= 1;
      else if (src.type === 'BUG_BOUNTY') isApp = true;
      else if (src.type === 'CLOUDSEK') isApp = (reqCounter % 10) <= 5;

      let targetAppId = null, targetInfraId = null, environment = Environment.PRODUCTION, assignedToId = null;
      let appDef = null, infraDef = null;

      if (isApp) {
        let validApps = [...aDefs];
        
        // ENFORCE SDLC STORY
        if (src.type === 'BUG_BOUNTY' || src.type === 'RED_TEAM') {
          validApps = validApps.filter(a => a.env === Environment.PRODUCTION);
        } else if (src.type === 'CVS' && (reqCounter % 10) < 3) {
          validApps = validApps.filter(a => a.env === Environment.DEVELOPMENT);
        } else if ((src.type === 'VAPT' || src.type === 'CLOUDSEK') && (reqCounter % 10) < 4) {
          validApps = validApps.filter(a => a.env === Environment.PRE_PRODUCTION);
        } else {
          validApps = validApps.filter(a => a.env === Environment.PRODUCTION);
        }

        if (src.type === 'BUG_BOUNTY') validApps = validApps.filter(a => a.net);
        if (src.type === 'RED_TEAM') validApps = validApps.filter(a => a.crit === 'Critical');
        
        if (validApps.length === 0) validApps = aDefs.filter(a => a.env === Environment.PRODUCTION);
        
        // 1. Calculate dynamic weight for each app to enforce Risk-Based Assignment
        const appWeights = validApps.map(a => {
          // Zero-Vulnerability Target Apps: Low-risk, non-internet-facing, no PII (~4 apps)
          const isZeroVulnTarget = a.crit === 'Low' && a.net === false && a.pii === false;
          if (isZeroVulnTarget) return 0; // Force zero requests

          let weight = 10;
          if (a.env === Environment.PRODUCTION) weight += 20;
          else if (a.env === Environment.PRE_PRODUCTION) weight += 10;
          else if (a.env === Environment.DEVELOPMENT) weight += 2;
          
          if (a.crit === 'Critical') weight += 30;
          
          // Tier 1 - Critical Production "Stars": Production + BIA + Internet Facing + Contains PII (~8 apps)
          const isTierOneStar = a.env === Environment.PRODUCTION && a.bia === true && a.net === true && a.pii === true;
          if (isTierOneStar) weight += 100;
          
          // Force baseline distribution: heavily weight apps that haven't received a request yet
          if (appUsage[a.appId] === 0) {
            weight += 1000;
          }

          return weight;
        });

        const totalWeight = appWeights.reduce((val, sum) => val + sum, 0);
        let randWeight = ((reqCounter * 23) % 100) / 100 * totalWeight;
        for (let i = 0; i < validApps.length; i++) {
          if (randWeight < appWeights[i]) {
            appDef = validApps[i];
            break;
          }
          randWeight -= appWeights[i];
        }
        if (!appDef) appDef = validApps[0]; // Fallback

        appUsage[appDef.appId]++;

        targetAppId = aMap[appDef.appId];
        environment = appDef.env;
        assignedToId = uMap[appDef.oe];
      } else {
        let validInfra = [...iDefs];
        
        if (src.type === 'CVS' && (reqCounter % 10) < 3) {
           validInfra = validInfra.filter(i => i.env === Environment.DEVELOPMENT);
        } else if ((src.type === 'VAPT' || src.type === 'CLOUDSEK') && (reqCounter % 10) < 4) {
           validInfra = validInfra.filter(i => i.env === Environment.PRE_PRODUCTION);
        } else {
           validInfra = validInfra.filter(i => i.env === Environment.PRODUCTION);
        }
        
        if (validInfra.length === 0) validInfra = iDefs.filter(i => i.env === Environment.PRODUCTION);

        validInfra.sort((a, b) => infraUsage[a.sid] - infraUsage[b.sid]);
        const poolSize = Math.max(1, Math.floor(validInfra.length * 0.3));
        const pool = validInfra.slice(0, poolSize);
        infraDef = pool[(reqCounter * 7) % pool.length];
        infraUsage[infraDef.sid]++;

        targetInfraId = iMap[infraDef.sid];
        environment = infraDef.env;
        assignedToId = uMap[infraDef.oe];
      }

      // Status
      let status: RequestStatus = RequestStatus.OPEN;
      let submittedAt = null, startedAt = null, closedAt = null;
      
      if (ageDays > 150) {
        status = RequestStatus.CLOSED;
        submittedAt = new Date(initiatedOn.getTime() + 86400000);
        startedAt = new Date(submittedAt.getTime() + 86400000 * 3);
        closedAt = new Date(startedAt.getTime() + 86400000 * 30);
      } else if (ageDays > 60) {
        const r = (reqCounter * 7 % 100) / 100;
        if (r < 0.6) {
          status = RequestStatus.CLOSED;
          closedAt = new Date(now.getTime() - 86400000 * 10);
        }
        else if (r < 0.8) status = RequestStatus.REVALIDATION;
        else status = RequestStatus.PATCHING;
      } else if (ageDays > 30) {
        const r = (reqCounter * 13 % 100) / 100;
        if (r < 0.2) status = RequestStatus.CLOSED;
        else if (r < 0.5) status = RequestStatus.PATCHING;
        else if (r < 0.9) status = RequestStatus.IN_PROGRESS;
        else status = RequestStatus.REVALIDATION;
      } else if (ageDays > 10) {
        const r = (reqCounter * 17 % 100) / 100;
        if (r < 0.3) status = RequestStatus.IN_PROGRESS;
        else if (r < 0.7) status = RequestStatus.PATCHING;
        else if (r < 0.9) status = RequestStatus.SUBMITTED;
        else status = RequestStatus.OPEN;
      } else {
        status = ((reqCounter % 2) === 0) ? RequestStatus.OPEN : RequestStatus.SUBMITTED;
      }

      if (status !== RequestStatus.OPEN && !submittedAt) {
        submittedAt = new Date(initiatedOn.getTime() + 86400000 * ((reqCounter % 3) + 1));
      }
      if ((status === RequestStatus.IN_PROGRESS || status === RequestStatus.PATCHING || status === RequestStatus.REVALIDATION || status === RequestStatus.CLOSED) && !startedAt) {
        startedAt = new Date(submittedAt!.getTime() + 86400000 * ((reqCounter % 5) + 1));
      }

      let initiator;
      const analystRand = (reqCounter * 23 % 100) / 100;
      if (analystRand < 0.40) initiator = secAnalysts[3]; // 40% to Priya
      else if (analystRand < 0.60) initiator = secAnalysts[0]; // 20%
      else if (analystRand < 0.80) initiator = secAnalysts[1]; // 20%
      else initiator = secAnalysts[2]; // 20%
      const reqId = `${src.type}-${initiatedOn.getFullYear()}-${String(reqCounter++).padStart(4, '0')}`;
      
      let assessmentMeta = {};
      let partner = null;
      let programmeUrl = null;

      if (src.type === 'VAPT') {
        partner = (reqCounter % 2 === 0) ? 'SecureLayer7' : 'Qualys';
        const vaptType = (reqCounter % 3 === 0) ? 'PRE_RELEASE' : 'PERIODIC';
        assessmentMeta = { vaptType, scope: isApp ? appDef?.name : infraDef?.sn };
      } else if (src.type === 'BUG_BOUNTY') {
        partner = (reqCounter % 2 === 0) ? 'HackerOne' : 'BugCrowd';
        programmeUrl = `https://${partner.toLowerCase()}.com/msil-bounty`;
        const bbType = (reqCounter % 4 === 0) ? 'Managed Disclosure' : 'Responsible Disclosure';
        assessmentMeta = { programme: partner, type: bbType };
      } else if (src.type === 'RED_TEAM') {
        partner = 'Cobalt.io';
        const rtRand = (reqCounter * 11 % 100) / 100;
        const team = rtRand < 0.5 ? 'External Red Team' : (rtRand < 0.8 ? 'Internal Red Team' : 'Purple Team Validation');
        assessmentMeta = { team, techniques: 'Full kill-chain simulation' };
      } else if (src.type === 'CLOUDSEK') {
        partner = 'CloudSEK XVigil';
        const csRand = (reqCounter * 19 % 100) / 100;
        const monType = csRand < 0.4 ? 'Attack Surface Exposure' : (csRand < 0.7 ? 'Credential Leak' : (csRand < 0.9 ? 'Brand Monitoring' : 'Dark Web Monitoring'));
        assessmentMeta = { monitoringCategory: monType, integrationId: 'CSK-9901' };
      }

      let finalAssignedToId = assignedToId;
      if (status === RequestStatus.OPEN || status === RequestStatus.SUBMITTED) {
        // Needs triage or approval. 30% to Security Lead, 70% to Security Analyst.
        finalAssignedToId = (reqCounter % 10) < 3 ? uMap['aanya.sharma@msil.in'] : uMap[initiator.email];
      } else if (status === RequestStatus.IN_PROGRESS || status === RequestStatus.REVALIDATION) {
        // Pentest running or patching done and needs verification. Tracked by Analyst.
        finalAssignedToId = uMap[initiator.email];
      } else if (status === RequestStatus.PATCHING) {
        // Pentest done, findings shared. App/Infra Owner needs to remediate.
        finalAssignedToId = assignedToId;
      } else if (status === RequestStatus.CLOSED) {
        // Most end up with the App Owner, some with the Analyst.
        finalAssignedToId = (reqCounter % 10) > 7 ? uMap[initiator.email] : assignedToId;
      }

      reqDefs.push({
        reqId,
        source: src.type as any,
        environment,
        status,
        targetAppId,
        targetInfraId,
        initiatedById: uMap[initiator.email],
        assignedToId: finalAssignedToId,
        initiatedOn,
        submittedAt,
        startedAt,
        closedAt,
        partner,
        programmeUrl,
        assessmentMeta,
        slaCompliance: 80 + (reqCounter % 21) // 80-100%
      });
    }
  }

  await prisma.securityRequest.createMany({
    data: reqDefs,
    skipDuplicates: true
  });
  console.log(`✅ Security Requests (${reqDefs.length})`);

  // ── 10. FINDINGS (Wave 2.3) ────────────────────────────────────────────────
  const allRequests = await prisma.securityRequest.findMany({
    select: { 
      id: true, 
      source: true, 
      reqId: true, 
      initiatedOn: true, 
      environment: true,
      targetApp: { select: { criticality: true, internetAccessible: true, biaApp: true, type: true } }
    }
  });

  const findingDefs: any[] = [];
  let findingCounter = 1;

  for (const req of allRequests) {
    let baseFindings = 1; // Default baseline

    if (req.targetApp) {
      const app = req.targetApp;
      // 1. Criticality Multiplier
      if (app.criticality === 'Critical') baseFindings += 2;
      else if (app.criticality === 'High') baseFindings += 1;
      else if (app.criticality === 'Low') baseFindings -= 1;

      // 2. Internet Facing
      if (app.internetAccessible) baseFindings += 1;

      // 3. BIA App
      if (app.biaApp) baseFindings += 1;

      // 4. Environment
      if (req.environment === Environment.PRODUCTION) baseFindings += 1;
      else if (req.environment === Environment.DEVELOPMENT) baseFindings -= 1;

      // 5. App Type
      if (app.type === 'WEB_APPLICATION') baseFindings += 1;
      else if (app.type === 'API') baseFindings += 0;
    } else {
      // Infrastructure fallback
      if (req.environment === Environment.PRODUCTION) baseFindings += 1;
    }

    // Source specific constraints (deterministic using initiatedOn as a pseudo-random seed)
    let pseudoRand = (findingCounter * 7 % 100) / 100; // 0 to 0.99
    
    let numFindings = Math.max(1, Math.floor(baseFindings * (0.8 + pseudoRand * 0.4))); // ±20% variance deterministically

    // Cap based on source to keep realism
    if (req.source === 'BUG_BOUNTY') numFindings = Math.min(numFindings, 3);
    else if (req.source === 'CLOUDSEK') numFindings = Math.min(numFindings, 5);
    else if (req.source === 'RED_TEAM') numFindings = Math.min(numFindings, 4);

    for (let i = 0; i < numFindings; i++) {
      const findingId = `FND-${req.initiatedOn.getFullYear()}-${String(findingCounter++).padStart(4, '0')}`;
      
      let title = '';
      let description = '';
      let recommendation = '';
      let cvssScore: number | null = null;
      let severity: Severity = Severity.MEDIUM;
      let status: FindingStatus = FindingStatus.ACCEPTED;
      let evidence = 'Log payload: {\"status\": 403, \"error\": \"Access Denied\"}';

      // Source-specific logic
      if (req.source === 'VAPT') {
        const vaptIssues = [
          { t: 'Cross-Site Scripting (XSS) in Search', s: Severity.HIGH },
          { t: 'SQL Injection in Login', s: Severity.CRITICAL },
          { t: 'Insecure Direct Object Reference (IDOR)', s: Severity.HIGH },
          { t: 'Missing Security Headers', s: Severity.LOW },
          { t: 'Outdated TLS Version', s: Severity.MEDIUM },
          { t: 'Information Disclosure via Stack Trace', s: Severity.MEDIUM },
          { t: 'Server version fingerprinting', s: Severity.INFORMATIONAL }
        ];
        const issue = vaptIssues[findingCounter % vaptIssues.length];
        title = issue.t; severity = issue.s;
        
        const r = (findingCounter * 13 % 100) / 100;
        if (r < 0.7) status = FindingStatus.ACCEPTED;
        else if (r < 0.8) status = FindingStatus.INFORMATIONAL;
        else if (r < 0.9) status = FindingStatus.FALSE_POSITIVE;
        else status = FindingStatus.DUPLICATE;
        
      } else if (req.source === 'BUG_BOUNTY') {
        const bbIssues = [
          { t: 'Subdomain Takeover on docs.msil.in', s: Severity.HIGH },
          { t: 'Business Logic Flaw in Checkout', s: Severity.CRITICAL },
          { t: 'API Key Exposure in JS Source', s: Severity.HIGH },
          { t: 'Reflected XSS on Contact Form', s: Severity.MEDIUM },
          { t: 'Missing Rate Limiting', s: Severity.LOW },
          { t: 'Clickjacking Vulnerability', s: Severity.LOW }
        ];
        const issue = bbIssues[findingCounter % bbIssues.length];
        title = issue.t; severity = issue.s;

        // BB has more duplicates/OOS
        const r = (findingCounter * 17 % 100) / 100;
        if (r < 0.4) status = FindingStatus.ACCEPTED;
        else if (r < 0.7) status = FindingStatus.DUPLICATE; // high duplicates in BB
        else if (r < 0.9) status = FindingStatus.FALSE_POSITIVE;
        else status = FindingStatus.CLOSED; // Using CLOSED to represent Out-of-Scope

      } else if (req.source === 'CVS') {
        const cvsIssues = [
          { t: 'CVE-2021-44228 Log4Shell Vulnerability', s: Severity.CRITICAL },
          { t: 'OpenSSH 8.2p1 Vulnerability', s: Severity.HIGH },
          { t: 'Apache Tomcat Outdated Package', s: Severity.MEDIUM },
          { t: 'Weak SSH Ciphers Enabled', s: Severity.LOW },
          { t: 'Unpatched Kernel Vulnerability', s: Severity.HIGH },
          { t: 'TLS 1.0 Enabled', s: Severity.MEDIUM },
          { t: 'Default configuration files present', s: Severity.INFORMATIONAL }
        ];
        const issue = cvsIssues[findingCounter % cvsIssues.length];
        title = issue.t; severity = issue.s;
        
        // CVS produces noise
        const r = (findingCounter * 19 % 100) / 100;
        if (r < 0.5) status = FindingStatus.ACCEPTED;
        else if (r < 0.7) status = FindingStatus.FALSE_POSITIVE;
        else if (r < 0.85) status = FindingStatus.INFORMATIONAL;
        else status = FindingStatus.DUPLICATE;
        
      } else if (req.source === 'CLOUDSEK') {
        const csIssues = [
          { t: 'Exposed S3 Bucket without ACL', s: Severity.HIGH },
          { t: 'Public Storage Blob Detected', s: Severity.MEDIUM },
          { t: 'IAM Role with Over-permissive Policies', s: Severity.HIGH },
          { t: 'Hardcoded Secret in Public Repository', s: Severity.CRITICAL },
          { t: 'Unprotected Management Port Exposed', s: Severity.HIGH },
          { t: 'Unverified Third-party Application Consent', s: Severity.LOW }
        ];
        const issue = csIssues[findingCounter % csIssues.length];
        title = issue.t; severity = issue.s;
        
        const r = (findingCounter * 23 % 100) / 100;
        if (r < 0.6) status = FindingStatus.ACCEPTED;
        else if (r < 0.8) status = FindingStatus.FALSE_POSITIVE;
        else status = FindingStatus.INFORMATIONAL;

      } else if (req.source === 'RED_TEAM') {
        const rtIssues = [
          { t: 'Domain Admin Privilege Escalation', s: Severity.CRITICAL },
          { t: 'Service Account Credential Abuse', s: Severity.HIGH },
          { t: 'Lateral Movement via WMI', s: Severity.HIGH },
          { t: 'Weak Network Segmentation Bypass', s: Severity.CRITICAL },
          { t: 'Detection Gap in EDR Coverage', s: Severity.MEDIUM },
          { t: 'Kerberoasting Vulnerability', s: Severity.HIGH }
        ];
        const issue = rtIssues[findingCounter % rtIssues.length];
        title = issue.t; severity = issue.s;
        
        // Red team findings are highly vetted
        const r = (findingCounter * 29 % 100) / 100;
        if (r < 0.85) status = FindingStatus.ACCEPTED;
        else if (r < 0.95) status = FindingStatus.INFORMATIONAL;
        else status = FindingStatus.CLOSED; // Risk Accepted equivalent
      }

      // ENFORCE SDLC STORY - Align Severity
      if (req.environment === Environment.DEVELOPMENT) {
        // Dev is mostly Low/Medium. Cap at High.
        if (severity === Severity.CRITICAL) severity = Severity.MEDIUM;
        if (severity === Severity.HIGH && (findingCounter % 2 === 0)) severity = Severity.LOW;
      } else if (req.environment === Environment.PRE_PRODUCTION) {
        // Pre-Prod has moderate findings, no criticals to show release readiness
        if (severity === Severity.CRITICAL) severity = Severity.HIGH;
      }

      // Generate CVSS based on severity
      if (severity === Severity.CRITICAL) cvssScore = ((((findingCounter * 31) % 10) / 10) * 1.0 + 9.0).toFixed(1) as any;
      else if (severity === Severity.HIGH) cvssScore = ((((findingCounter * 37) % 20) / 20) * 1.9 + 7.0).toFixed(1) as any;
      else if (severity === Severity.MEDIUM) cvssScore = ((((findingCounter * 41) % 30) / 30) * 2.9 + 4.0).toFixed(1) as any;
      else if (severity === Severity.LOW) cvssScore = ((((findingCounter * 43) % 40) / 40) * 3.9 + 0.1).toFixed(1) as any;
      
      cvssScore = cvssScore ? parseFloat(cvssScore as any) : null;

      description = `Discovered ${title} during ${req.source} assessment. This finding poses a ${severity} risk to the environment.`;
      recommendation = `Apply relevant patches, reconfigure access controls, or sanitize input immediately to resolve ${title}.`;

      findingDefs.push({
        findingId,
        title,
        description,
        severity,
        status,
        sourceType: req.source as any,
        sourceId: req.id,
        cvssScore,
        recommendation,
        evidence,
        convertedToVulnerability: false,
        createdAt: new Date(req.initiatedOn.getTime() + (findingCounter % 24) * 3600000), // created shortly after request
      });
    }
  }

  console.log(`✅ Findings generated in-memory (${findingDefs.length})`);

  // ── 11. VULNERABILITIES (Wave 2.4) ─────────────────────────────────────────
  const acceptedFindings = findingDefs
    .filter(f => f.status === 'ACCEPTED')
    .map(f => {
      // Simulate the joined relation that findMany would have returned
      const req = allRequests.find(r => r.id === f.sourceId);
      return {
        ...f,
        securityRequest: req
      };
    });

  const crypto = require('crypto');
  const vulnDefs: any[] = [];
  const slaDefs: any[] = [];
  
  // To format vuln IDs like VAPT-2025-0042-001
  const reqVulnCounters: Record<string, number> = {};

  const nowTime = new Date('2026-06-30T00:00:00Z').getTime();

  // Pre-calculate Zero-Active-Vulnerability Targets: Non-critical, Corporate IT (~7 apps)
  const zeroActiveUUIDs = aDefs
    .filter(a => a.bia === false && a.crit === 'Medium' && a.dept === 'Corporate IT')
    .map(a => aMap[a.appId])
    .filter(id => id);

  let priyaRevalCount = 0;
  let aanyaRevalCount = 0;
  let analystRoundRobinIdx = 0;
  const priyaId = uMap['analyst@sentinel.local'];
  const aanyaId = uMap['aanya.sharma@msil.in'];
  const otherAnalysts = secAnalysts.filter(u => u.role === 'SECURITY_ANALYST' && u.email !== 'analyst@sentinel.local');


  let vIndex = 0;
  for (const f of acceptedFindings) {
    vIndex++;
    const req = f.securityRequest;
    if (!req) continue;

    if (!reqVulnCounters[req.reqId]) reqVulnCounters[req.reqId] = 1;
    const vulnCounter = String(reqVulnCounters[req.reqId]++).padStart(3, '0');
    const vulnId = `${req.reqId}-${vulnCounter}`;

    const ageDays = (nowTime - f.createdAt.getTime()) / (1000 * 3600 * 24);
    
    // SLA Days based on Severity
    let slaDays = 180;
    if (f.severity === 'CRITICAL') slaDays = 30;
    else if (f.severity === 'HIGH') slaDays = 45;
    else if (f.severity === 'MEDIUM') slaDays = 90;
    else if (f.severity === 'INFORMATIONAL') slaDays = 365;

    const dueDate = new Date(f.createdAt.getTime() + slaDays * 86400000);

    // Determine target breach based on Environment and Severity
    let willBreach = false;
    let rBreach = (vIndex * 31 % 100) / 100;

    if (req.environment === Environment.DEVELOPMENT) {
      willBreach = false; // 100% compliance
    } else if (req.environment === Environment.PRE_PRODUCTION) {
      // 90-95% compliance -> ~5-10% breach probability
      if (f.severity === 'CRITICAL') willBreach = rBreach < 0.15;
      else if (f.severity === 'HIGH') willBreach = rBreach < 0.10;
      else if (f.severity === 'MEDIUM') willBreach = rBreach < 0.05;
      else willBreach = rBreach < 0.01;
    } else {
      // Production: 80-85% compliance -> ~15-20% breach probability
      if (f.severity === 'CRITICAL') willBreach = rBreach < 0.35; 
      else if (f.severity === 'HIGH') willBreach = rBreach < 0.25; 
      else if (f.severity === 'MEDIUM') willBreach = rBreach < 0.10; 
      else willBreach = rBreach < 0.05; 
    }

    // Determine Status & closedAt deterministically
    let status = 'OPEN';
    let closedAt = null;

    let rStatus = (vIndex * 37 % 100) / 100; // 0 to 0.99
    
    // Shift distribution based on environment (Dev/Pre-Prod close more)
    if (req.environment === Environment.DEVELOPMENT) {
      rStatus = Math.min(0.99, rStatus + 0.15); // Push towards CLOSED
    } else if (req.environment === Environment.PRE_PRODUCTION) {
      rStatus = Math.min(0.99, rStatus + 0.05); // Push towards CLOSED
    }

    if (ageDays < 15) {
      // New findings (Mostly OPEN/ASSIGNED)
      if (rStatus < 0.50) status = 'OPEN';
      else if (rStatus < 0.70) status = 'ASSIGNED';
      else status = 'IN_PROGRESS';
    } else if (ageDays < 60) {
      // Mid-age findings (More progressive)
      if (rStatus < 0.45) status = 'OPEN';
      else if (rStatus < 0.55) status = 'ASSIGNED';
      else if (rStatus < 0.70) status = 'IN_PROGRESS';
      else if (rStatus < 0.85) status = 'PATCHED';
      else status = 'PENDING_REVALIDATION';
    } else {
      // Older findings (Higher chance of closure, but still backlogged)
      if (rStatus < 0.40) status = 'OPEN';
      else if (rStatus < 0.50) status = 'ASSIGNED';
      else if (rStatus < 0.65) status = 'IN_PROGRESS';
      else if (rStatus < 0.75) status = 'PATCHED';
      else if (rStatus < 0.82) status = 'PENDING_REVALIDATION';
      else {
        status = 'CLOSED';
        closedAt = new Date(f.createdAt.getTime() + 86400000 * ((rStatus - 0.82) * 300 + 5));
        if (closedAt.getTime() > nowTime) closedAt = new Date(nowTime - 86400000);
      }
    }

    // Force "Zero Active Vulnerabilities" targets based on metadata
    if (req.targetAppId && zeroActiveUUIDs.includes(req.targetAppId)) {
      status = 'CLOSED';
      closedAt = new Date(f.createdAt.getTime() + 86400000 * ((vIndex % 5) + 1));
      willBreach = false;
    }

    if (status === 'CLOSED' && !closedAt) {
      closedAt = new Date(f.createdAt.getTime() + 86400000 * 2);
    }

    const isBreached = (status !== 'CLOSED' && nowTime > dueDate.getTime()) || (status === 'CLOSED' && closedAt && closedAt.getTime() > dueDate.getTime());
    let breachedAt = null;
    if (isBreached) {
      breachedAt = dueDate;
    }

    const vulnerabilityId = crypto.randomUUID();

    let vulnAssignedToId = req.assignedToId;
    if (status === 'PENDING_REVALIDATION' || status === 'CLOSED') {
      let assignTo = null;
      if (status === 'PENDING_REVALIDATION') {
        if (priyaRevalCount < 4) {
          assignTo = priyaId;
          priyaRevalCount++;
        } else if (aanyaRevalCount < 2) {
          assignTo = aanyaId;
          aanyaRevalCount++;
        }
      }
      
      if (!assignTo && otherAnalysts.length > 0) {
        assignTo = uMap[otherAnalysts[analystRoundRobinIdx % otherAnalysts.length].email];
        analystRoundRobinIdx++;
      }
      
      if (assignTo) {
        vulnAssignedToId = assignTo;
      }
    }

    vulnDefs.push({
      id: vulnerabilityId,
      vulnId,
      requestId: req.id,
      source: req.source,
      environment: req.environment,
      type: f.title,
      shortDesc: f.title,
      description: f.description,
      severity: f.severity,
      cvss: f.cvssScore,
      cve: f.cveId,
      status: status as any,
      assignedToId: vulnAssignedToId,
      poc: f.evidence,
      remediation: f.recommendation,
      closedAt,
      slaDueDate: dueDate,
      createdAt: f.createdAt,
    });

    slaDefs.push({
      id: crypto.randomUUID(),
      vulnerabilityId,
      dueDate,
      isBreached,
      breachedAt,
      createdAt: f.createdAt,
    });
  }

  await prisma.vulnerability.createMany({
    data: vulnDefs,
    skipDuplicates: true
  });
  
  await prisma.slaTracking.createMany({
    data: slaDefs,
    skipDuplicates: true
  });



  console.log(`✅ Vulnerabilities (${vulnDefs.length}) & SLA Trackers`);

  // ── 12. VULNERABILITY LIFECYCLE (Wave 2.5) ───────────────────────────────
  const allVulns = await prisma.vulnerability.findMany({
    include: { request: true }
  });

  const lifecycleDefs: any[] = [];
  
  // Fast reverse lookup for user details in memory
  const getUserMeta = (userId: string | null) => {
    if (!userId) return { name: 'System User', role: 'SYSTEM' };
    const email = Object.keys(uMap).find(key => uMap[key] === userId);
    if (!email) return { name: 'Unknown', role: 'UNKNOWN' };
    const u = uDefs.find(x => x.email === email);
    return u ? { name: u.name, role: u.role } : { name: 'Unknown', role: 'UNKNOWN' };
  };

  for (const v of allVulns) {
    const secAnalystId = v.request.initiatedById;
    const ownerId = v.request.assignedToId;
    
    const secAnalyst = getUserMeta(secAnalystId);
    const owner = getUserMeta(ownerId);
    
    const t0 = v.createdAt;
    
    const targetStatus = v.status;
    let currentT = new Date(t0.getTime());

    const addLog = (fromStatus: string | null, toStatus: string, actorId: string | null, actorName: string, actorRole: string, remarks: string) => {
      lifecycleDefs.push({
        id: crypto.randomUUID(),
        vulnerabilityId: v.id,
        fromStatus: fromStatus as any,
        toStatus: toStatus as any,
        actorId,
        actorName,
        actorRole,
        remarks,
        timestamp: new Date(currentT.getTime())
      });
      // advance time by 1 to 15 days deterministically
      currentT = new Date(currentT.getTime() + (lifecycleDefs.length % 14 + 1) * 86400000);
    };

    // 1. OPEN
    addLog(null, 'OPEN', secAnalystId, secAnalyst.name, secAnalyst.role, 'Vulnerability logged and opened.');
    if (targetStatus === 'OPEN') continue;

    // 2. ASSIGNED
    addLog('OPEN', 'ASSIGNED', secAnalystId, secAnalyst.name, secAnalyst.role, 'Assigned to asset owner for remediation.');
    if (targetStatus === 'ASSIGNED') continue;

    // 3. IN_PROGRESS
    addLog('ASSIGNED', 'IN_PROGRESS', ownerId, owner.name, owner.role, 'Investigation and patching started.');
    if (targetStatus === 'IN_PROGRESS') continue;

    // 4. PATCHED
    addLog('IN_PROGRESS', 'PATCHED', ownerId, owner.name, owner.role, 'Patch applied to environment. Ready for revalidation.');
    if (targetStatus === 'PATCHED') continue;

    // 5. PENDING_REVALIDATION
    addLog('PATCHED', 'PENDING_REVALIDATION', secAnalystId, secAnalyst.name, secAnalyst.role, 'Revalidation scan scheduled.');
    
    // Simulate Failed Revalidation loop deterministically if target is CLOSED or PENDING_REVALIDATION
    const hasFailedLoop = (lifecycleDefs.length % 100) > 85; // 15% chance
    if (hasFailedLoop && (targetStatus === 'CLOSED' || targetStatus === 'PENDING_REVALIDATION')) {
      addLog('PENDING_REVALIDATION', 'IN_PROGRESS', secAnalystId, secAnalyst.name, secAnalyst.role, 'Revalidation failed. Vulnerability still exists.');
      
      addLog('IN_PROGRESS', 'PATCHED', ownerId, owner.name, owner.role, 'Secondary patch applied after failure.');
      
      addLog('PATCHED', 'PENDING_REVALIDATION', secAnalystId, secAnalyst.name, secAnalyst.role, 'Second revalidation scan scheduled.');
    }

    if (targetStatus === 'PENDING_REVALIDATION') continue;

    // 6. CLOSED
    if (v.closedAt && currentT.getTime() < v.closedAt.getTime()) {
      currentT = new Date(v.closedAt.getTime());
    }
    addLog('PENDING_REVALIDATION', 'CLOSED', secAnalystId, secAnalyst.name, secAnalyst.role, 'Revalidation successful. Vulnerability closed.');
  }

  await prisma.vulnerabilityLifecycleLog.createMany({
    data: lifecycleDefs,
    skipDuplicates: true
  });
  console.log(`✅ Vulnerability Lifecycle Logs (${lifecycleDefs.length})`);

  // ── 13. DATA CONSISTENCY RECONCILIATION ────────────────────────────────────
  console.log(`\n🔄 Reconciling canonical metrics...`);
  const reqsToUpdate = await prisma.securityRequest.findMany({
    include: {
      findings: true,
      vulnerabilities: {
        include: { slaTracking: true }
      }
    }
  });

  let updateCount = 0;
  for (const r of reqsToUpdate) {
    const totalFindings = r.vulnerabilities.length; // Only count tracked vulnerabilities (Verified Findings)
    const openFindings = r.vulnerabilities.filter(v => v.status !== 'CLOSED').length;
    const critFindings = r.vulnerabilities.filter(v => v.severity === 'CRITICAL' && v.status !== 'CLOSED').length;
    const highFindings = r.vulnerabilities.filter(v => v.severity === 'HIGH' && v.status !== 'CLOSED').length;
    
    let slaCompliance = 100;
    const slaTrackedVulns = r.vulnerabilities.filter(v => v.status !== 'CLOSED' && v.slaTracking);
    if (slaTrackedVulns.length > 0) {
      const withinSla = slaTrackedVulns.filter(v => !v.slaTracking?.isBreached).length;
      slaCompliance = Math.round((withinSla / slaTrackedVulns.length) * 100);
    }

    let correctedStatus = r.status;
    if (totalFindings === 0) correctedStatus = 'CLOSED' as any;
    else if (openFindings === 0) correctedStatus = 'CLOSED' as any;
    else if (correctedStatus === 'CLOSED' && openFindings > 0) correctedStatus = 'IN_PROGRESS' as any;

    await prisma.securityRequest.update({
      where: { id: r.id },
      data: {
        totalFindings,
        openFindings,
        critFindings,
        highFindings,
        slaCompliance,
        status: correctedStatus as any,
      }
    });
    updateCount++;
  }
  console.log(`✅ Reconciled ${updateCount} Security Requests with actual Finding/Vuln payloads.`);

  // ── 13.5. PLATFORM SETTINGS ──────────────────────────────────────────────────
  console.log(`\n⚙️ Seeding AI Platform Settings...`);
  const aiSettings = [
    { category: SettingCategory.AI, key: 'ai.enabled', value: 'true', dataType: SettingDataType.BOOLEAN, label: 'Enable AI Features' },
    { category: SettingCategory.AI, key: 'ai.provider', value: 'OPENROUTER', dataType: SettingDataType.STRING, label: 'AI Provider' },
    { category: SettingCategory.AI, key: 'ai.apiKey', value: '', dataType: SettingDataType.STRING, label: 'API Key' },
    { category: SettingCategory.AI, key: 'ai.model', value: 'google/gemini-2.5-flash', dataType: SettingDataType.STRING, label: 'AI Model' },
    { category: SettingCategory.AI, key: 'ai.temperature', value: '0.2', dataType: SettingDataType.STRING, label: 'Temperature' },
    { category: SettingCategory.AI, key: 'ai.maxTokens', value: '1024', dataType: SettingDataType.INTEGER, label: 'Max Output Tokens' },
    { category: SettingCategory.AI, key: 'ai.timeoutMs', value: '30000', dataType: SettingDataType.INTEGER, label: 'Request Timeout (ms)' },
  ];

  for (const s of aiSettings) {
    await prisma.platformSetting.upsert({
      where: { key: s.key },
      update: { value: s.value },
      create: s,
    });
  }
  console.log(`✅ AI Platform Settings (${aiSettings.length})`);

  // ── 14. SEED VALIDATION REPORT ──────────────────────────────────────────────
  console.log(`\n🔍 Running Automated Data Consistency Checks...`);
  const errors: string[] = [];

  // 1. Orphan Checks
  const orphanApps = await prisma.application.count({ where: { ownerId: null } });
  if (orphanApps > 0) errors.push(`${orphanApps} Applications are missing an Owner.`);

  const orphanReqs = await prisma.securityRequest.count({ where: { targetAppId: null, targetInfraId: null } });
  if (orphanReqs > 0) errors.push(`${orphanReqs} Security Requests are not linked to any asset.`);



  const orphanedVulnsFromAssets = await prisma.vulnerability.count({
    where: {
      request: {
        targetAppId: null,
        targetInfraId: null
      }
    }
  });
  if (orphanedVulnsFromAssets > 0) errors.push(`${orphanedVulnsFromAssets} Vulnerabilities are not linked to an Application or Infrastructure asset.`);

  // 2. SLA Range Checks
  const invalidSla = await prisma.securityRequest.count({
    where: { OR: [{ slaCompliance: { lt: 0 } }, { slaCompliance: { gt: 100 } }] }
  });
  if (invalidSla > 0) errors.push(`${invalidSla} Security Requests have SLA outside 0-100 range.`);

  // 3. Totals Verification
  const totalVulnsRaw = await prisma.vulnerability.count();
  const reqTotalSum = (await prisma.securityRequest.findMany()).reduce((acc, curr) => acc + curr.totalFindings, 0);

  if (totalVulnsRaw !== reqTotalSum) {
    errors.push(`Findings Metrics Mismatch: Total Vulns(${totalVulnsRaw}) != Request Sum(${reqTotalSum})`);
  }

  const openVulnsRaw = await prisma.vulnerability.count({ where: { status: { not: 'CLOSED' } } });
  const reqOpenSum = (await prisma.securityRequest.findMany()).reduce((acc, curr) => acc + curr.openFindings, 0);
  if (openVulnsRaw !== reqOpenSum) {
    errors.push(`Open Metrics Mismatch: Vulns(${openVulnsRaw}) | Request Sum(${reqOpenSum})`);
  }

  if (errors.length > 0) {
    console.error(`\n❌ SEED VALIDATION FAILED! The dataset is inconsistent.`);
    errors.forEach(e => console.error(`   - ${e}`));
    throw new Error('Seed Validation Failed. See above errors.');
  } else {
    console.log(`✅ Seed Validation Passed! 100% Data Consistency Achieved.`);
  }
}

main().catch(console.error).finally(() => prisma.$disconnect());
