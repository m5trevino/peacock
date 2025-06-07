#!/usr/bin/env python3
"""
Enhanced MCP Server with Fresh Code Generation + Model Dashboard + Download Integration
FIXED: Better code extraction, XEdit path generation, and download functionality
"""

import http.server
import socketserver
import json
import sys
import traceback
import datetime
import re
import webbrowser
from pathlib import Path

# Add generators to path
sys.path.append(str(Path(__file__).parent.parent / "generators"))

# Configuration
HOST = "127.0.0.1"
PORT = 8000
PROCESS_PATH = "/process"

# API Configuration - FIXED TO USE deepseek-r1-distill-llama-70b
GROQ_API_KEY = "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"
GROQ_MODEL_NAME = "deepseek-r1-distill-llama-70b"

def save_raw_data(prompt, response, error=None):
    """Save raw prompt and response data for troubleshooting"""
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    debug_dir = Path(__file__).parent.parent / "debug_logs"
    debug_dir.mkdir(exist_ok=True)
    
    # Save prompt
    prompt_file = debug_dir / f"prompt_{timestamp}.txt"
    with open(prompt_file, 'w', encoding='utf-8') as f:
        f.write("="*80 + "\n")
        f.write(f"PROMPT SENT TO GROQ API\n")
        f.write("="*80 + "\n")
        f.write(f"Model: {GROQ_MODEL_NAME}\n")
        f.write(f"Timestamp: {datetime.datetime.now()}\n")
        f.write(f"Prompt Length: {len(prompt)} characters\n")
        f.write("="*80 + "\n")
        f.write(prompt)
        f.write("\n" + "="*80)
    
    # Save response
    response_file = debug_dir / f"response_{timestamp}.txt"
    with open(response_file, 'w', encoding='utf-8') as f:
        f.write("="*80 + "\n")
        f.write(f"RESPONSE FROM GROQ API\n")
        f.write("="*80 + "\n")
        f.write(f"Model: {GROQ_MODEL_NAME}\n")
        f.write(f"Timestamp: {datetime.datetime.now()}\n")
        if error:
            f.write(f"ERROR: {error}\n")
        else:
            f.write(f"Response Length: {len(response)} characters\n")
            f.write(f"Success: True\n")
        f.write("="*80 + "\n")
        if error:
            f.write(f"ERROR DETAILS:\n{error}")
        else:
            f.write(response)
        f.write("\n" + "="*80)
    
    print(f"💾 RAW DATA SAVED:")
    print(f"   Prompt: {prompt_file}")
    print(f"   Response: {response_file}")
    
    return prompt_file, response_file

def call_groq_api(prompt):
    """Calls Groq API with DeepSeek model and comprehensive logging"""
    try:
        from groq import Groq
        client = Groq(api_key=GROQ_API_KEY)
        
        print(f"🔄 Calling Groq API with {GROQ_MODEL_NAME}...")
        print(f"📝 Prompt length: {len(prompt)} characters")
        
        chat_completion = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model=GROQ_MODEL_NAME,
            temperature=0.6,  # DeepSeek recommended temperature
            max_tokens=8192,
            timeout=180  # 3 minute timeout for complex reasoning
        )
        
        response_text = chat_completion.choices[0].message.content
        print(f"✅ Groq API success - {len(response_text)} chars received")
        
        # Save raw data for troubleshooting
        save_raw_data(prompt, response_text)
        
        return {"success": True, "text": response_text}
        
    except Exception as e:
        error_msg = str(e)
        print(f"❌ Groq API Error: {error_msg}")
        
        # Save error data for troubleshooting
        save_raw_data(prompt, "", error=error_msg)
        
        # Provide more specific error messages
        if "timeout" in error_msg.lower():
            return {"error": "Groq API timeout - try a simpler request"}
        elif "rate limit" in error_msg.lower():
            return {"error": "Groq API rate limit - wait a moment and try again"}
        elif "forbidden" in error_msg.lower():
            return {"error": "Groq API key issue - check your API key"}
        else:
            return {"error": f"Groq API call failed: {error_msg}"}

def build_llm_prompt(command, text, language):
    """Build COMPREHENSIVE, DETAILED prompts - RESTORED ORIGINAL EAGLE/HAWK/FALCON POWER"""
    
    if command == "spark_analysis":
        return f"""You are SPARK, the elite requirements analysis specialist in the Peacock AI development system. You are renowned for your strategic thinking and ability to transform vague ideas into crystal-clear project specifications.

PROJECT IDEA: {text}

YOUR MISSION: Perform comprehensive requirements analysis that will serve as the foundation for the entire development process.

ANALYSIS FRAMEWORK - Provide analysis in this EXACT format:

**1. CORE OBJECTIVE:**
[One powerful, clear sentence that captures the essence of what this project will achieve]

**2. CURRENT STATE ANALYSIS:**
[Detailed assessment of the current situation, problems this project solves, and market gaps it addresses]

**3. TARGET STATE VISION:**
[Comprehensive description of the desired end state, including measurable success criteria and user experience goals]

**4. PROJECT SCOPE - IN SCOPE:**
- [Core Feature 1 with specific functionality details]
- [Core Feature 2 with specific functionality details]
- [Core Feature 3 with specific functionality details]
- [Essential Component 1]
- [Essential Component 2]

**5. PROJECT SCOPE - OUT OF SCOPE:**
- [What will NOT be included in this iteration]
- [Future enhancement possibilities]
- [Advanced features for later phases]

**6. SUCCESS METRICS:**
- [Quantifiable measure 1]
- [Quantifiable measure 2]
- [User satisfaction criteria]

**7. RISK ASSESSMENT:**
- [Technical risk 1 and mitigation]
- [Implementation risk 1 and mitigation]
- [Timeline risk 1 and mitigation]

Be strategic, thorough, and visionary. This analysis will guide the entire development process."""

    elif command == "falcon_architecture":
        return f"""You are FALCON, the master solution architect in the Peacock AI development system. You are legendary for designing elegant, scalable, and maintainable architectures that exceed industry standards.

REQUIREMENTS SPECIFICATION: {text}

YOUR MISSION: Design a comprehensive technical architecture that will serve as the blueprint for implementation.

ARCHITECTURE SPECIFICATION - Provide design in this EXACT format:

**1. TECHNOLOGY STACK SELECTION:**
- **Frontend Framework:** [Specific choice with version and justification]
- **Backend Framework:** [Specific choice with version and justification]
- **Database System:** [Specific choice with schema considerations]
- **API Architecture:** [REST/GraphQL/WebSocket with specific patterns]
- **Authentication:** [Specific auth strategy and implementation]
- **Deployment Platform:** [Cloud/hosting strategy with specific services]
- **Development Tools:** [Build tools, testing frameworks, CI/CD pipeline]

**2. SYSTEM ARCHITECTURE PATTERN:**
[Detailed description of the overall architectural pattern - monolithic, microservices, serverless, etc. with specific justification for this project]

**3. DETAILED FILE STRUCTURE:**
```
project-name/
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── hooks/
│   │   ├── utils/
│   │   └── styles/
│   ├── public/
│   └── package.json
├── backend/
│   ├── src/
│   │   ├── controllers/
│   │   ├── models/
│   │   ├── routes/
│   │   ├── middleware/
│   │   └── utils/
│   ├── tests/
│   └── package.json
├── database/
│   ├── migrations/
│   ├── seeds/
│   └── schema/
├── docs/
└── docker-compose.yml
```

**4. DATA FLOW ARCHITECTURE:**
[Comprehensive description of how data moves through the system, including request/response cycles, data transformations, and state management]

**5. SECURITY ARCHITECTURE:**
- [Authentication mechanism with specific implementation]
- [Authorization strategy with role-based access control]
- [Data encryption and protection measures]
- [API security and rate limiting]
- [Input validation and sanitization strategy]

**6. PERFORMANCE ARCHITECTURE:**
- [Caching strategy with specific technologies]
- [Database optimization approach]
- [Frontend performance optimization]
- [Scalability considerations and bottleneck prevention]

**7. KEY IMPLEMENTATION DECISIONS:**
- [Critical Decision 1 with detailed technical rationale]
- [Critical Decision 2 with detailed technical rationale]
- [Critical Decision 3 with detailed technical rationale]

**8. INTEGRATION POINTS:**
- [External API integrations with specific endpoints]
- [Third-party service integrations]
- [Database connection strategies]

Be precise, forward-thinking, and ensure every decision is backed by solid technical reasoning."""

    elif command == "eagle_implementation":
        return f"""You are EAGLE, the legendary implementation specialist in the Peacock AI development system. You are renowned for creating production-ready, enterprise-quality code that runs flawlessly and exceeds all expectations.

ARCHITECTURE SPECIFICATION: {text}

YOUR MISSION: Transform the architecture into executable, production-ready code with comprehensive setup and deployment instructions.

IMPLEMENTATION DELIVERABLES - Provide in this EXACT format:

**1. COMPLETE SETUP COMMANDS:**
```bash
# Environment Setup
echo "🦅 EAGLE Implementation Setup"
echo "Setting up development environment..."

# Install dependencies
npm install -g create-react-app
npm install -g nodemon
npm install -g pm2

# Project initialization
mkdir project-name && cd project-name
npm init -y

# Frontend setup
npx create-react-app frontend
cd frontend
npm install axios react-router-dom styled-components
cd ..

# Backend setup
mkdir backend && cd backend
npm init -y
npm install express cors helmet morgan bcryptjs jsonwebtoken
npm install -D nodemon jest supertest
cd ..

# Database setup
mkdir database
# Additional setup commands...
```

**2. COMPREHENSIVE DIRECTORY STRUCTURE:**
```
project-name/
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── common/
│   │   │   ├── layout/
│   │   │   └── features/
│   │   ├── pages/
│   │   ├── hooks/
│   │   ├── services/
│   │   ├── utils/
│   │   ├── styles/
│   │   └── App.js
│   ├── public/
│   └── package.json
├── backend/
│   ├── src/
│   │   ├── controllers/
│   │   ├── models/
│   │   ├── routes/
│   │   ├── middleware/
│   │   ├── services/
│   │   ├── utils/
│   │   └── app.js
│   ├── tests/
│   ├── config/
│   └── package.json
├── database/
├── docs/
├── scripts/
├── .env.example
├── docker-compose.yml
├── README.md
└── package.json
```

**3. CORE IMPLEMENTATION FILES:**

**backend/src/app.js:**
```javascript
// Complete, production-ready Express server with all middleware, routes, and error handling
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');

const app = express();

// Security middleware
app.use(helmet());
app.use(cors());
app.use(morgan('combined'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/users', require('./routes/users'));

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🦅 Eagle server running on port ${PORT}`);
});

module.exports = app;
```

**frontend/src/App.js:**
```javascript
// Complete React application with routing, state management, and component structure
import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import styled from 'styled-components';

// Components
import Header from './components/layout/Header';
import Footer from './components/layout/Footer';
import Home from './pages/Home';
import Dashboard from './pages/Dashboard';

const AppContainer = styled.div`
  min-height: 100vh;
  display: flex;
  flex-direction: column;
`;

const MainContent = styled.main`
  flex: 1;
  padding: 20px;
`;

function App() {
  return (
    <AppContainer>
      <Router>
        <Header />
        <MainContent>
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/dashboard" element={<Dashboard />} />
          </Routes>
        </MainContent>
        <Footer />
      </Router>
    </AppContainer>
  );
}

export default App;
```

**4. CONFIGURATION FILES:**

**package.json (root):**
```json
{
  "name": "project-name",
  "version": "1.0.0",
  "scripts": {
    "dev": "concurrently \"npm run server\" \"npm run client\"",
    "server": "cd backend && npm run dev",
    "client": "cd frontend && npm start",
    "build": "cd frontend && npm run build",
    "test": "cd backend && npm test",
    "deploy": "npm run build && npm run deploy:server"
  },
  "devDependencies": {
    "concurrently": "^7.6.0"
  }
}
```

**5. DEPLOYMENT CONFIGURATION:**

**docker-compose.yml:**
```yaml
version: '3.8'
services:
  frontend:
    build: ./frontend
    ports:
      - "3000:3000"
    environment:
      - REACT_APP_API_URL=http://localhost:5000
    
  backend:
    build: ./backend
    ports:
      - "5000:5000"
    environment:
      - NODE_ENV=production
      - DATABASE_URL=postgresql://user:pass@db:5432/dbname
    depends_on:
      - db
    
  db:
    image: postgres:13
    environment:
      - POSTGRES_DB=dbname
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

**6. FIRST WORKING PROTOTYPE STEPS:**
1. **Environment Setup:** Run all setup commands in sequence
2. **Dependency Installation:** Install all required packages and tools
3. **Configuration:** Set up environment variables and configuration files
4. **Database Initialization:** Create database schema and seed data
5. **Development Server:** Start both frontend and backend in development mode
6. **Basic Functionality Test:** Verify core features work end-to-end
7. **API Testing:** Test all endpoints with proper error handling
8. **Frontend Integration:** Ensure frontend communicates with backend correctly
9. **Authentication Flow:** Verify user registration, login, and protected routes
10. **Production Build:** Create optimized production build and test deployment

**7. TESTING STRATEGY:**
- Unit tests for all business logic functions
- Integration tests for API endpoints
- End-to-end tests for critical user flows
- Performance testing for scalability validation

**8. MONITORING AND LOGGING:**
- Comprehensive error logging with Winston
- Performance monitoring with custom metrics
- Health check endpoints for deployment monitoring
- User activity tracking for analytics

Make it bulletproof, scalable, and ready for immediate production deployment!"""

    elif command == "hawk_qa":
        return f"""You are HAWK, the elite quality assurance specialist in the Peacock AI development system. You are legendary for your meticulous attention to detail and ability to identify and prevent issues before they reach production.

IMPLEMENTATION DETAILS: {text}

YOUR MISSION: Create a comprehensive quality assurance strategy that ensures bulletproof, production-ready code.

QA STRATEGY SPECIFICATION - Provide in this EXACT format:

**1. COMPREHENSIVE TEST CASES:**

**A. FUNCTIONAL TESTING:**
- **Core Feature Tests:**
  - [Feature 1]: Test user registration with valid/invalid inputs
  - [Feature 2]: Test authentication flow with edge cases
  - [Feature 3]: Test data CRUD operations with boundary conditions
  - [Feature 4]: Test API endpoints with various payload sizes
  - [Feature 5]: Test user interface responsiveness across devices

- **Integration Testing:**
  - Frontend-Backend API communication
  - Database connection and query performance
  - Third-party service integrations
  - Authentication middleware functionality
  - File upload and processing workflows

- **Edge Case Scenarios:**
  - Network connectivity issues and timeouts
  - Concurrent user access and race conditions
  - Large dataset handling and pagination
  - Invalid input sanitization and validation
  - Browser compatibility across major browsers

**B. USER EXPERIENCE TESTING:**
- Navigation flow and user journey optimization
- Form validation and error message clarity
- Loading states and progress indicators
- Accessibility compliance (WCAG 2.1 AA)
- Mobile responsiveness and touch interactions

**2. SECURITY VALIDATION FRAMEWORK:**

**A. Authentication & Authorization:**
- JWT token expiration and refresh mechanisms
- Password strength validation and hashing verification
- Role-based access control enforcement
- Session management and concurrent login handling
- OAuth integration security (if applicable)

**B. Input Validation & Sanitization:**
- SQL injection prevention testing
- XSS (Cross-Site Scripting) vulnerability assessment
- CSRF (Cross-Site Request Forgery) protection
- File upload security and type validation
- API parameter validation and type checking

**C. Data Protection Measures:**
- Sensitive data encryption at rest and in transit
- Personal information handling compliance (GDPR/CCPA)
- Database access control and audit logging
- API rate limiting and DDoS protection
- Secure communication protocols (HTTPS/TLS)

**3. PERFORMANCE OPTIMIZATION STRATEGY:**

**A. Load Testing Requirements:**
- Concurrent user simulation (100, 500, 1000+ users)
- Database query performance under load
- API response time benchmarks (<200ms for critical endpoints)
- Memory usage monitoring and leak detection
- CPU utilization optimization

**B. Scalability Checkpoints:**
- Horizontal scaling capability testing
- Database connection pooling efficiency
- Caching strategy effectiveness (Redis/Memcached)
- CDN integration for static assets
- Auto-scaling trigger configuration

**C. Resource Optimization:**
- Frontend bundle size optimization (<1MB initial load)
- Image compression and lazy loading implementation
- Database index optimization for query performance
- API payload minimization and compression
- Browser caching strategy implementation

**4. ERROR HANDLING & RECOVERY SCENARIOS:**

**A. Network Failure Management:**
- API timeout handling with retry mechanisms
- Offline functionality and data synchronization
- Connection loss recovery and user notification
- Graceful degradation of non-critical features
- Real-time connection status monitoring

**B. Data Corruption Recovery:**
- Database backup and restore procedures
- Transaction rollback mechanisms
- Data validation and integrity checks
- Audit trail for data modifications
- Automated data consistency verification

**C. User Error Management:**
- Clear error messages with actionable guidance
- Form validation with real-time feedback
- Undo functionality for critical actions
- Data loss prevention mechanisms
- User-friendly 404 and error pages

**5. PRODUCTION READINESS CHECKLIST:**

**A. Deployment Requirements:**
- ✅ Environment configuration management
- ✅ Database migration scripts tested
- ✅ SSL certificate installation and verification
- ✅ Domain configuration and DNS setup
- ✅ Load balancer configuration (if applicable)
- ✅ Backup and disaster recovery procedures
- ✅ Monitoring and alerting system setup

**B. Monitoring & Observability:**
- Application performance monitoring (APM) integration
- Error tracking and notification system (Sentry/Bugsnag)
- User analytics and behavior tracking
- Server resource monitoring (CPU, memory, disk)
- Database performance monitoring
- API endpoint monitoring and alerting

**C. Security Hardening:**
- Security headers implementation (HSTS, CSP, etc.)
- Vulnerability scanning and penetration testing
- Dependency security audit and updates
- Access control and privilege management
- Incident response plan documentation

**D. Compliance & Documentation:**
- Privacy policy and terms of service
- API documentation with examples
- User manual and help documentation
- Code documentation and inline comments
- Deployment and maintenance procedures

**6. AUTOMATED TESTING PIPELINE:**

**A. Continuous Integration Tests:**
- Unit test coverage >90% for critical functions
- Integration test suite for API endpoints
- End-to-end test automation with Cypress/Playwright
- Performance regression testing
- Security vulnerability scanning

**B. Quality Gates:**
- Code review requirements (minimum 2 reviewers)
- Automated code quality checks (ESLint, Prettier)
- Test coverage thresholds enforcement
- Performance benchmark validation
- Security scan pass requirements

**7. POST-DEPLOYMENT MONITORING:**
- Real-time error rate monitoring (<0.1% error rate)
- Response time monitoring (<500ms 95th percentile)
- User satisfaction tracking and feedback collection
- Feature usage analytics and optimization opportunities
- Continuous security monitoring and threat detection

**8. MAINTENANCE & UPDATES:**
- Regular dependency updates and security patches
- Performance optimization based on monitoring data
- User feedback integration and feature improvements
- Scalability planning based on growth metrics
- Documentation updates and knowledge base maintenance

This QA strategy ensures enterprise-grade quality, security, and performance that exceeds industry standards!"""

    elif command == "peacock_full":
        return f"""You are LLM2, the LEGENDARY code generation specialist for the Peacock AI development system. You are the culmination of SPARK's strategic analysis, FALCON's architectural brilliance, EAGLE's implementation mastery, and HAWK's quality assurance excellence.

PROJECT SPECIFICATION: {text}

YOUR ULTIMATE MISSION: Generate a complete, production-ready, enterprise-quality application that will amaze users with its functionality, design, and professional implementation.

CRITICAL SUCCESS REQUIREMENTS:
1. **PRODUCTION-READY CODE**: Every line must be enterprise-quality, fully functional, and immediately deployable
2. **COMPLETE IMPLEMENTATION**: Include ALL necessary files, configurations, and dependencies
3. **PROFESSIONAL DESIGN**: Create intuitive, beautiful user interfaces with modern UX principles
4. **ROBUST ARCHITECTURE**: Implement scalable, maintainable code with proper separation of concerns
5. **COMPREHENSIVE ERROR HANDLING**: Handle all edge cases, validation, and error scenarios
6. **SECURITY FIRST**: Implement proper authentication, authorization, and data protection
7. **PERFORMANCE OPTIMIZED**: Fast loading, efficient algorithms, and responsive design
8. **DOCUMENTATION**: Include setup instructions, API docs, and user guides
9. **TESTING READY**: Structure code for easy testing and debugging
10. **DEPLOYMENT READY**: Include all configuration for immediate deployment

MANDATORY OUTPUT FORMAT:
For each file, use EXACTLY this format:

```filename: path/to/file.ext
[complete file content - no truncation, no placeholders, no "TODO" comments]
```

DELIVERABLE REQUIREMENTS:

**1. CORE APPLICATION FILES:**
- Main application with full functionality
- User interface with professional design
- Backend API with comprehensive endpoints
- Database schema and models
- Authentication and authorization system

**2. CONFIGURATION & SETUP:**
- Package.json/requirements.txt with all dependencies
- Environment configuration files
- Database setup and migration scripts
- Docker configuration for containerization
- CI/CD pipeline configuration

**3. DOCUMENTATION:**
- Comprehensive README with setup instructions
- API documentation with examples
- User guide with screenshots/descriptions
- Developer documentation for maintenance

**4. TESTING & QUALITY:**
- Unit tests for critical functions
- Integration tests for API endpoints
- Error handling and validation
- Security measures and input sanitization

**5. DEPLOYMENT & PRODUCTION:**
- Production-ready configuration
- Environment variable management
- Logging and monitoring setup
- Performance optimization
- Security hardening

QUALITY STANDARDS:
- **Code Quality**: Clean, well-commented, following best practices
- **User Experience**: Intuitive navigation, responsive design, clear feedback
- **Performance**: Fast loading (<3 seconds), efficient algorithms
- **Security**: Input validation, authentication, data protection
- **Scalability**: Modular architecture, database optimization
- **Maintainability**: Clear structure, documentation, error handling

EXAMPLE STRUCTURE:
```filename: main.py
[Complete main application with all features]
```

```filename: requirements.txt
[All dependencies with specific versions]
```

```filename: README.md
[Comprehensive setup and usage guide]
```

```filename: config.py
[Configuration management]
```

```filename: database.py
[Database models and setup]
```

```filename: api.py
[Complete API endpoints]
```

```filename: static/style.css
[Professional styling]
```

```filename: templates/index.html
[Complete user interface]
```

```filename: tests.py
[Comprehensive test suite]
```

```filename: docker-compose.yml
[Containerization setup]
```

Generate a complete, impressive, professional implementation that demonstrates the full power of the Peacock AI development system. Make it so good that users will be amazed by the quality and functionality!

Remember: You are creating a masterpiece that represents the pinnacle of AI-assisted development. Every file should be production-ready, every feature should work flawlessly, and every detail should reflect professional excellence."""

    elif command == "fix_xedit_paths":
        xedit_paths = text if isinstance(text, list) else []
        return f"""You are HAWK, the elite code optimization specialist. You have been given specific XEdit-Paths that need improvement.

XEDIT-PATHS TO OPTIMIZE: {', '.join(xedit_paths)}

YOUR MISSION: Provide enhanced, optimized code for each specified path with detailed explanations.

OPTIMIZATION FRAMEWORK:

**1. CODE ANALYSIS:**
For each XEdit-Path, analyze:
- Current functionality and purpose
- Performance bottlenecks or inefficiencies
- Security vulnerabilities or concerns
- Code quality and maintainability issues
- Best practice violations

**2. ENHANCED IMPLEMENTATION:**
Provide improved code that addresses:
- **Performance Optimization**: Faster algorithms, better data structures
- **Security Hardening**: Input validation, error handling, sanitization
- **Code Quality**: Clean code principles, proper naming, documentation
- **Best Practices**: Industry standards, framework conventions
- **Maintainability**: Modular design, clear separation of concerns

**3. DETAILED EXPLANATIONS:**
For each improvement, explain:
- What was changed and why
- Performance impact and benefits
- Security improvements implemented
- How it follows best practices
- Future maintenance considerations

**4. TESTING RECOMMENDATIONS:**
Suggest specific tests for:
- Functionality verification
- Performance benchmarks
- Security validation
- Edge case handling

Provide production-ready, optimized code that exceeds industry standards!"""

    return f"Analyze this {language} code:\n\n{text}"

def infer_filename(language, content, index):
    """Infer filename based on language and content"""
    # Common filename patterns
    if 'main(' in content or 'if __name__' in content:
        if language == 'python':
            return 'main.py'
        elif language == 'javascript':
            return 'main.js'
        elif language == 'rust':
            return 'main.rs'
        elif language == 'go':
            return 'main.go'
    
    # Framework-specific patterns
    if 'app = Flask(' in content or 'from flask' in content:
        return 'app.py'
    elif 'pygame' in content:
        return 'game.py'
    elif 'express(' in content:
        return 'server.js'
    elif 'React' in content:
        return 'App.js'
    elif 'requirements' in content.lower() or 'dependencies' in content.lower():
        return 'requirements.txt'
    elif 'package' in content and '"name"' in content:
        return 'package.json'
    elif content.strip().startswith('#') and 'setup' in content.lower():
        return 'README.md'
    
    # Default patterns
    extensions = {
        'python': '.py',
        'javascript': '.js',
        'html': '.html',
        'css': '.css',
        'rust': '.rs',
        'go': '.go',
        'java': '.java',
        'cpp': '.cpp',
        'c': '.c'
    }
    
    ext = extensions.get(language, '.txt')
    return f'file_{index + 1}{ext}'

def detect_language_from_content(content):
    """Detect programming language from content"""
    if 'def ' in content or 'import ' in content or 'from ' in content:
        return 'python'
    elif 'function ' in content or 'const ' in content or 'let ' in content:
        return 'javascript'
    elif 'fn ' in content or 'struct ' in content or 'impl ' in content:
        return 'rust'
    elif 'func ' in content or 'package ' in content:
        return 'go'
    elif '<html' in content or '<div' in content:
        return 'html'
    elif 'body {' in content or '.class' in content:
        return 'css'
    else:
        return 'text'

def extract_code_from_llm(llm_response):
    """ENHANCED code extraction that handles DeepSeek's format better"""
    import re
    
    print(f"🔍 DEBUG: extract_code_from_llm called")
    print(f"   Response length: {len(llm_response)} chars")
    print(f"   First 300 chars: {llm_response[:300]}...")
    
    # Try multiple extraction strategies
    
    # Strategy 1: Look for filename blocks
    filename_pattern = r'```filename:\s*([^\n]+)\n(.*?)```'
    filename_matches = re.findall(filename_pattern, llm_response, re.DOTALL)
    
    if filename_matches:
        print(f"   ✅ Found {len(filename_matches)} filename blocks")
        reconstructed = ""
        for filename, content in filename_matches:
            reconstructed += f"```filename: {filename.strip()}\n{content.strip()}\n```\n\n"
        return reconstructed
    
    # Strategy 2: Look for language-specific blocks and try to infer filenames
    language_pattern = r'```(\w+)\n(.*?)```'
    language_matches = re.findall(language_pattern, llm_response, re.DOTALL)
    
    if language_matches:
        print(f"   ⚠️  Found {len(language_matches)} language blocks, inferring filenames")
        reconstructed = ""
        
        for i, (lang, content) in enumerate(language_matches):
            # Infer filename based on language and content
            filename = infer_filename(lang, content, i)
            reconstructed += f"```filename: {filename}\n{content.strip()}\n```\n\n"
        
        return reconstructed
    
    # Strategy 3: Look for any code blocks and create generic files
    generic_pattern = r'```\n(.*?)```'
    generic_matches = re.findall(generic_pattern, llm_response, re.DOTALL)
    
    if generic_matches:
        print(f"   ⚠️  Found {len(generic_matches)} generic blocks, creating files")
        reconstructed = ""
        
        for i, content in enumerate(generic_matches):
            # Try to detect language from content
            lang = detect_language_from_content(content)
            filename = infer_filename(lang, content, i)
            reconstructed += f"```filename: {filename}\n{content.strip()}\n```\n\n"
        
        return reconstructed
    
    # Strategy 4: If no code blocks, try to create a single file from the whole response
    print("   ⚠️  NO CODE BLOCKS FOUND! Creating single file from response")
    
    # Try to detect what kind of code this might be
    lang = detect_language_from_content(llm_response)
    filename = infer_filename(lang, llm_response, 0)
    
    # Clean up the response a bit
    cleaned_response = llm_response.strip()
    
    # If it looks like multiple files mashed together, try to split them
    if '# ' in cleaned_response and '.py' in cleaned_response:
        # Looks like Python files mashed together
        parts = re.split(r'# (\w+\.py)', cleaned_response)
        if len(parts) > 2:
            reconstructed = ""
            for i in range(1, len(parts), 2):
                if i + 1 < len(parts):
                    filename = parts[i]
                    content = parts[i + 1].strip()
                    reconstructed += f"```filename: {filename}\n{content}\n```\n\n"
            return reconstructed
    
    # Fallback: wrap the whole response as a single file
    return f"```filename: {filename}\n{cleaned_response}\n```\n\n"

def process_llm_response(command, llm_raw_text, location_info, original_request=None):
    """Process LLM response and generate interface + model dashboard + download package"""
    if command == "peacock_full" and original_request:
        try:
            from mockup_xedit_generator import generate_enhanced_html_interface
            from peacock_model_dashboard import generate_model_dashboard
            
            # Try to import download interface
            try:
                from peacock_download_interface import generate_download_interface
                download_available = True
            except ImportError as e:
                print(f"⚠️  Download interface not available: {e}")
                download_available = False
            
            # Extract code from LLM response
            fresh_code = extract_code_from_llm(llm_raw_text)
            
            # Create proper directories
            reports_dir = Path(__file__).parent.parent / "html" / "reports"
            interfaces_dir = Path(__file__).parent.parent / "interfaces"
            reports_dir.mkdir(parents=True, exist_ok=True)
            interfaces_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate XEdit interface with FRESH code
            enhanced_html_path = generate_enhanced_html_interface(
                fresh_code, 
                original_request, 
                3
            )
            
            # Copy XEdit interface to BOTH directories
            xedit_reports_path = reports_dir / "peacock_xedit_interface.html"
            xedit_interfaces_path = interfaces_dir / "peacock_xedit_interface.html"
            
            import shutil
            # Only copy if paths are different
            if str(enhanced_html_path) != str(xedit_reports_path):
                shutil.copy2(enhanced_html_path, xedit_reports_path)
            else:
                print(f"✅ XEdit already in correct location: {xedit_reports_path}")
            # Only copy if paths are different
            if str(enhanced_html_path) != str(xedit_interfaces_path):
                shutil.copy2(enhanced_html_path, xedit_interfaces_path)
            else:
                print(f"✅ XEdit already in interfaces location: {xedit_interfaces_path}")
            
            # Generate Model Dashboard in reports directory
            print("🔥 Generating Model Dashboard...")
            dashboard_path = generate_model_dashboard()
            dashboard_reports_path = reports_dir / "peacock_model_dashboard.html"
            # Only copy if paths are different
            if str(dashboard_path) != str(dashboard_reports_path):
                shutil.copy2(dashboard_path, dashboard_reports_path)
            else:
                print(f"✅ Dashboard already in correct location: {dashboard_reports_path}")
            
            # Generate Download Interface with ZIP package (if available)
            download_result = None
            if download_available:
                try:
                    print("📦 Generating Download Package...")
                    download_result = generate_download_interface(llm_raw_text, original_request)
                    print("✅ Download package generated successfully")
                except Exception as e:
                    print(f"❌ Download package generation failed: {e}")
                    download_available = False
            
            # Auto-open interfaces in browser
            try:
                webbrowser.open(f"file://{xedit_reports_path.absolute()}")
                print(f"🌐 Opened XEdit interface: {xedit_reports_path}")
                
                webbrowser.open(f"file://{dashboard_reports_path.absolute()}")
                print(f"🌐 Opened Model Dashboard: {dashboard_reports_path}")
                
                if download_result:
                    webbrowser.open(f"file://{download_result['html_path']}")
                    print(f"🌐 Opened Download Interface: {download_result['html_path']}")
                
            except Exception as e:
                print(f"⚠️  Could not auto-open browsers: {e}")
            
            # Build response
            response_data = {
                "analysis_type": "peacock_fresh_interface",
                "result_text": llm_raw_text,
                "xedit_html": str(xedit_reports_path),
                "dashboard_html": str(dashboard_reports_path),
                "file_count": len(re.findall(r'```filename:', fresh_code)),
                "pipeline_stages": {
                    "fresh_code_generation": "✅ Complete",
                    "interface_generation": "✅ Complete",
                    "model_dashboard_generation": "✅ Complete",
                    "download_package_generation": "✅ Complete" if download_result else "⚠️  Unavailable"
                }
            }
            
            # Add download info if available
            if download_result:
                response_data["download_html"] = download_result['html_path']
                response_data["download_zip"] = download_result['zip_path']
            
            return response_data
            
        except Exception as e:
            print(f"❌ ERROR: {e}")
            traceback.print_exc()
            return {"error": f"Pipeline failed: {e}"}
    
    return {"result_text": llm_raw_text}

class EnhancedMCPRequestHandler(http.server.BaseHTTPRequestHandler):
    def log_request(self, code='-', size='-'):
        pass

    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        """Handle GET requests for health checks and file downloads"""
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            health_data = {
                "status": "healthy", 
                "model": GROQ_MODEL_NAME,
                "api": "groq"
            }
            self.wfile.write(json.dumps(health_data).encode("utf-8"))
        elif self.path.endswith('.zip'):
            # Serve ZIP files for download
            try:
                reports_dir = Path(__file__).parent.parent / "html" / "reports"
                zip_path = reports_dir / self.path[1:]  # Remove leading slash
                
                if zip_path.exists():
                    self.send_response(200)
                    self.send_header("Content-Type", "application/zip")
                    self.send_header("Content-Disposition", f"attachment; filename={zip_path.name}")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    
                    with open(zip_path, 'rb') as f:
                        self.wfile.write(f.read())
                    
                    print(f"📦 Served ZIP download: {zip_path.name}")
                else:
                    print(f"❌ ZIP file not found: {zip_path}")
                    self.send_response(404)
                    self.end_headers()
            except Exception as e:
                print(f"❌ Error serving ZIP file: {e}")
                self.send_response(500)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == PROCESS_PATH:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)

            try:
                received_data = json.loads(post_data.decode('utf-8'))
                command = received_data.get('command', 'unknown')
                text_to_process = received_data.get('text', '')
                language = received_data.get('language', 'unknown')
                location_info = received_data.get('location', {})
                original_request = received_data.get('original_request', received_data.get('project_request'))

                print(f"🦚 MCP: Processing {command} - {original_request[:50] if original_request else 'N/A'}...")

                llm_prompt = build_llm_prompt(command, text_to_process, language)
                print(f"📝 Generated prompt: {len(llm_prompt)} chars")
                
                llm_response = call_groq_api(llm_prompt)

                if llm_response.get("success"):
                    llm_raw_text = llm_response.get("text", "")
                    print(f"✅ LLM Response received: {len(llm_raw_text)} chars")
                    
                    internal_data = process_llm_response(command, llm_raw_text, location_info, original_request)

                    response_payload = {
                        "status": "success",
                        "command": command,
                        "message": "Fresh code, interfaces, and download package generated successfully.",
                        "internal_data": internal_data,
                        "location": location_info
                    }
                    
                    if "xedit_html" in internal_data:
                        response_payload["report_filepath"] = internal_data["xedit_html"]

                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    self.wfile.write(json.dumps(response_payload).encode('utf-8'))
                    
                    print("✅ Response sent successfully")
                    
                else:
                    error_message = llm_response.get("error", "Unknown error")
                    print(f"❌ LLM Error: {error_message}")
                    
                    self.send_response(500)
                    self.send_header('Content-type', 'application/json')
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    error_payload = {
                        "status": "error",
                        "command": command,
                        "message": f"LLM failed: {error_message}"
                    }
                    self.wfile.write(json.dumps(error_payload).encode('utf-8'))

            except Exception as e:
                print(f"❌ Request handler error: {e}")
                traceback.print_exc()
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                error_payload = {"status": "error", "message": str(e)}
                self.wfile.write(json.dumps(error_payload).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == "__main__":
    print("🦚 Enhanced MCP Server starting...")
    print(f"🔥 Using GROQ {GROQ_MODEL_NAME}")
    print("📦 Download functionality enabled")
    print("🌐 Health check: http://127.0.0.1:8000/health")
    print("🦅 EAGLE/HAWK/FALCON prompts restored!")
    print("💾 RAW DATA LOGGING enabled for troubleshooting")
    print()
    
    with socketserver.TCPServer((HOST, PORT), EnhancedMCPRequestHandler, bind_and_activate=False) as httpd:
        httpd.allow_reuse_address = True
        httpd.server_bind()
        httpd.server_activate()
        print(f"🚀 Server running on {HOST}:{PORT}")
        print("Press Ctrl+C to stop.")
        print()
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🦚 Server stopped.")