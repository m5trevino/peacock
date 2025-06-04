LLM2 CODING INSTRUCTIONS
Role: Code Implementation Specialist
You are a coding specialist who receives structured technical specifications and implements them exactly as defined. You do NOT need to understand business context or end goals - just follow the technical blueprint provided.
Project Scope
Build a comprehensive car dealership management system based on the following structured specifications:

STAGE 1: SPARK REQUIREMENTS ANALYSIS
Core Objective

Unify all dealership operations into a single platform to optimize sales, customer engagement, inventory efficiency, and decision-making through real-time insights
Enhance profitability by reducing operational redundancies and improving transparency across inventory, sales, and customer lifetime value

Current State

Fragmented systems: Inventory, CRM, sales, and financing managed via spreadsheets/partial software
Manual processes slow data updates, causing stock discrepancies and missed sales opportunities
No centralized financing integration; deals often stall due to manual underwriting workflows
Ad-hoc reporting; dashboards lack real-time data and predictive insights

Target State

Unified, automated platform with real-time data flow across inventory, CRM, sales, financing, and reporting
Fully integrated customer journeys (prospecting to follow-up) with automated triggers
Real-time dashboards for inventory turnover, sales pipeline health, and ROI of marketing/financing campaigns
Seamless financing approvals in minutes, with API-linked banking partners

In Scope

Inventory Management: Automated stock tracking, reordering alerts, price optimization
CRM: 360° customer profiles, communication history, and sales team collaboration tools
Sales Pipeline: Opportunity tracking, deals forecasting, and commission automation
Financing Integration: API connections to banking/lease providers for rate quotes, application processes, and approval tracking
Real-Time Dashboard: Customizable widgets for KPIs
System Security: GDPR/PCI compliance, multi-factor authentication, access controls
Reporting Automation: Scheduled export, trend analytics, and customizable reports

Out of Scope

Vehicle manufacturing/procurement processes
Third-party vehicle delivery logistics
IoT-enabled in-store customer tracking
Social media marketing/ad platform integrations
Vehicle maintenance/repair system
Integration with non-sales departments
Custom add-ons for non-core dealership functions


STAGE 2: FALCON TECHNICAL ARCHITECTURE
Technology Stack

Frontend: React.js with Material-UI for UX (Web & dashboards) and React Native (Mobile Admin)
API & Services: Python (FastAPI) for backend services; Node.js (Express) for event-driven services
Database: Core: PostgreSQL 14+ with JSONB; Real-Time Analytics: TimescaleDB; Cache: Redis
Messaging Queue: Apache Kafka (or Confluent Cloud)
Real-Time Dashboard: Grafana + Elasticsearch
Third-Party Integration: REST APIs for banks, automakers, Google Maps
Cloud Platform: AWS (EC2, RDS, S3, Lambda, SNS/SQS)
CI/CD Pipelines: GitHub Actions or GitLab CI + Docker + Kubernetes
Security: OAuth2.0 (Auth0), TLS 1.3, JWT, OWASP secure coding practices

Architecture Pattern: Event-Driven Microservices

Core Modules as Services:

Inventory Service (manages stock, VINs, pricing)
CRM Service (contacts, customer history, email/marketing hooks)
Sales Pipeline Service (lead to sale lifecycle, quotes, deals)
Finance Service (loan applications, payment processing)
Reporting Service (aggregates data for dashboards)



File Structure (Monorepo Pattern)
project-root/
├── services/
│   ├── inventory/ (api/, models/, events/)
│   ├── crm/
│   ├── finance/
│   └── dashboard/ (dash/, etl/)
├── common/ (auth/, config/, logger/)
├── tooling/ (docker-compose.yml, k8s-manifests/, ci-cd/)
├── frontend/ (dashboard/)
└── third-party-interfaces/ (financing-gateway/)
Data Flow

Inventory Management: Dealers input via web UI → PostgreSQL → Kafka events → TimescaleDB views
Sales Pipeline: Customer details in CRM → PostgreSQL → sale_closed events → finance/inventory updates
Financing Integration: Loan applications to bank APIs → events → CRM/inventory state updates
Reporting: Kafka messages → TimescaleDB → dashboards; Historical reports via Redshift


STAGE 3: EAGLE IMPLEMENTATION PLAN
Setup Commands
bash# Initialize repository
mkdir car-dealership && cd car-dealership
git init
echo "node_modules/" > .gitignore
npm init -y

# Server setup
mkdir -p server/{src,prisma,migrations} && cd server
npm init -y
npm install express mongoose sequelize
npm install -D nodemon typescript @types/express
npx tsc --init
npx prisma init

# Client setup
cd ..
npx create-react-app client --template typescript
cd client
npm install react-chartjs-2 @types/react-router-dom
Database Configuration (Prisma Schema)
prismagenerator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model Car {
  id          Int        @id @default(autoincrement())
  vin         String    @unique
  make        String
  model       String
  stock       Int
  price       Decimal
  sold        Boolean   @default(false)
  salesRecord Sales[]
}

model Sales {
  id          Int       @id @default(autoincrement())
  carId       Car     @relation(fields: [carId], references: [id])
  customerId  String
  price       Decimal
  saleDate    DateTime @default(now())
}

model Customer {
  id        String   @id @default(uuid())
  name      String
  email     String  @unique
  phone     String?
  sales     Sales[] @relation("CustomerToSales")
}
Initial Code Scaffolding Required

Server-Side (API Foundation): Express app with CORS, routes, Prisma integration
Client-Side (Layout): React Router setup with Navbar, inventory/dashboard routes
Core Endpoints: CRUD operations for cars, customers, sales
Components: InventoryTable, CustomerForm, DashboardPage with Chart.js

First Working Prototype Features

Basic inventory listing and creation
Customer registration
Sales dashboard with sample chart
Backend API skeleton
Prisma-driven database interactions


STAGE 4: HAWK QA REQUIREMENTS
Test Cases Required

Inventory: Add/edit/delete with VIN validation, search/filters, concurrent purchases
CRM: CRUD operations, special characters, role-based access
Sales Pipeline: Lead tracking through stages, discount validation, abandoned deals
Financing: API integration testing, error handling, loan denial scenarios
Dashboard: Real-time updates, data accuracy, large dataset performance

Security Validation

Authentication with rate limiting and MFA
Authorization role testing
Data encryption and masking
SQL injection and XSS prevention
Third-party API security
Audit logging

Performance Requirements

Support 500 concurrent users
Dashboard render < 2 seconds
API response times ≤ 300ms
99.9% uptime SLA
Database scaling for 10k+ cars

Error Handling

Invalid user input validation
Database disconnection recovery
API failure graceful degradation
Concurrency conflict resolution
Network failure offline functionality

Production Readiness

Docker container security scans
CI/CD pipeline validation
Database backup/recovery testing
Third-party API integration verification
Monitoring and alerting setup
GDPR/PCI compliance validation


IMPLEMENTATION INSTRUCTIONS
Your task is to implement this system following the exact specifications above.
Start with:

Execute the setup commands
Create the directory structure
Implement the database schema
Build the initial code scaffolding
Create the first working prototype

Focus on getting a functional MVP that demonstrates:

Inventory management (add/list cars)
Basic CRM (customer registration)
Simple dashboard (sales visualization)
API endpoints working correctly

Do NOT:

Modify the requirements or architecture
Add features not specified
Use different technologies than specified
Skip the systematic implementation approach

Expected deliverable:
A working car dealership management system that can be run locally and demonstrates all core functionality specified in the requirements.
