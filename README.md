# SecureChain: AI + Blockchain Digital Security Platform

A comprehensive Flask-based cybersecurity SaaS platform for document authenticity verification, fraud prevention, secure record validation, and tamper-proof blockchain certification.

![Platform](https://img.shields.io/badge/Flask-3.1.1-blue) ![Python](https://img.shields.io/badge/Python-3.12+-green)

## Overview

SecureChain is an enterprise-ready digital security platform that combines artificial intelligence with blockchain technology to provide:

- **Document Verification**: Upload and verify documents with cryptographic proof of authenticity
- **Blockchain Ledger**: Immutable SHA256 hash chain for tamper detection  
- **AI Risk Analysis**: Automated risk scoring and fraud indicator detection
- **Incident Management**: Complete lifecycle tracking from open to resolved incidents
- **Role-Based Access Control**: Admin/User separation with delegated admin scopes
- **Two-Factor Authentication**: TOTP-based 2FA with manual approval workflows

## Key Features

### Core Security Capabilities

| Feature | Description |
|---------|-------------|
| CSV-backed Authentication | Role-based auth (admin/user) stored in users.csv |
| Password Hashing | bcrypt password hashing |
| CSRF Protection | Cross-site request forgery protection |
| Session Timeout | Auto-logout after configurable inactivity period |
| Login Rate Limiting | Attempt limiter with temporary lockout |
| File Validation | Type/MIME validation + upload size restrictions |

### Document Management Flow

```
User uploads -> Encryption at rest -> Admin verification -> Blockchain entry -> Certificate generation
```

### Blockchain Integration (app/blockchain.py)

The platform maintains an immutable ledger containing:
* Block number & timestamp  
* SHA256 file hash 
* Previous block hash link  
* Verification ID & Owner ID  

Every record modification creates traceable audit entries.

### AI Engine Module (app/ai_engine.py)

Automated analysis providing:
```python
{
    "risk_percentage": int,
    "authenticity_score": int,
    "fraud_indicator": str ("Low"|"Medium"|"High"),
    "security_summary": str,
    "explanation": str,
}
```

Risk factors analyzed:
* File extension profile (.exe, .js, .zip = high risk)
* Payload size patterns (>10MB triggers alerts)
* Version churn frequency  
* Blockchain integrity signals
  
### Incident Workflows  

Complete case management lifecycle:

```
open -> in_review -> resolved/closed + resolution_note logging per incident_id 
```

Evidence notes attach directly to each verification record.

## Project Structure  

```
securechain/
├── app/
│   ├── __init__.py          # Flask app factory & config setup  
│   ├── app.py               # Main application entry point    
│   ├── auth.py              # Authentication blueprints & helpers   
│   ├── routes.py            # All web routes (~2500 lines)       
│   ├── security.py          # Guards: rate limiting / encryption / activity logs 
│   ├── ai_engine.py         # Risk analysis / PDF report generation 
│   ├── blockchain.py        # Chain initialization / validation logic     
│   └── ...                  # Additional modules (alerts/jobs/monitoring/policy/api_access)
├── templates/               ; Jinja2 HTML templates (~25 pages)      
├── static/css/styles.css    ; Tailwind CSS styling                 
├── static/js/app.js         ; Frontend JavaScript                   
└── data/                    ; Runtime storage directory             
      *.csv                  ; Records/transfers/notifications/etc.
      *.json                 ; User profiles/blockchain state/etc.
```

## Quick Start  

**Prerequisites:** Python 3.12+ 

```bash  
# Navigate to project root
   
# Create virtual environment   
python -m venv .venv   

# Activate virtual environment   
# Windows PowerShell:    
.\venv\Scripts\Activate.ps1    

# macOS/Linux:    
source .venv/bin/activate   

# Install dependencies   
pip install -r requirements.txt   

# Run development server   
python app.py   

# Open browser at http://127.0.0.1:5000     
```  

## Demo Credentials  

Default accounts auto-created if missing from app/users.csv:

| Role     | Username  | Password     |
|:--------:|:---------:|:------------:|        
| Admin    | admin     | Admin@12345  |       
| User     | user      │ User@12345  |

> Change these credentials before production deployment!

## Web Routes Reference  

Public endpoints accessible without authentication:

```
GET  /                         Landing page showing verified count + health stats          
GET  /verify                   Public document verification form                             
POST /upload/public            Guest/anonymous upload endpoint                               
GET  /health                   Health check JSON endpoint                                    
```

Authenticated user routes require login session; role-specific routes enforce permissions via @role_required("admin").

Full route definitions available in app/routes.

## API Endpoints 

All return JSON unless otherwise specified; some require Bearer token authentication via /api/external/*.

**Analytics**
```http                                                                                    
GET api stats           Dashboard analytics snapshot                                    
```                      

**Verification**
```http                                                                                    
GET api verify/<vid>                Public single-ID check                                            
POST api upload/check             Pre-upload duplicate/risk evaluation                             POST api external verify/<vid>     API-key protected verify endpoint                                 
```                    


**Assistant**
```http                                                                                    
POST api chat                     AI Copilot chat interface                                       GET api incidents                 Role-aware incident queue API                                    GET api notifications       Notification stream                                                         GET api activities         Recent activity stream                                                        
```

For full API reference see documentation in code comments.

## Deployment Options                                             

### Docker Container                                                 

Build image locally then run containerized service:

docker build -t securechain .
docker run -p5000 :5000 --detach securechain                                              
 
For cloud platforms supporting Procfile format use gunicorn command specification above.


gunicorn workers handle concurrent requests efficiently across multiple processes within containerized environments.


--bind host IP address binding configuration ensures proper network accessibility when deploying behind reverse proxies like nginx or AWS ALB.


Production deployments should implement additional hardening measures beyond default configurations including database migration away from flat-file formats like SQLite/MySQL PostgreSQL instead storing sensitive assets securely using external secret managers rather than hardcoded values plus enabling TLS encryption through certificates signed by trusted certificate authorities while configuring centralized logging aggregation pipelines monitoring services such as DataDog New Relic Prometheus Grafana stack respectively.



Security recommendations continue implementing multi-factor authentication options integrating identity providers supporting SAML OAuth protocols alongside hardened key management solutions leveraging hardware security modules HSM cloud provider key management services KMS ensuring robust access controls throughout system architecture.



Comprehensive testing suite validates core functionality across multiple scenarios covering authentication flows authorization checks input sanitization edge cases error handling under various load conditions test coverage reports generated automatically during CI/CD pipeline execution validating expected behavior against defined acceptance criteria ensuring reliable consistent performance across all supported deployment configurations.



Project utilizes modular design principles separating concerns into distinct components responsible for specific functionality facilitating maintainability extensibility while following industry best practices established within Python web development community promoting clean code standards consistent naming conventions comprehensive inline documentation enabling seamless collaboration among team members working simultaneously on different features without introducing conflicts regressions unexpected side effects during ongoing development iterations continuous improvement cycles focused on delivering value incrementally validated through automated testing feedback loops early detection issues reducing overall maintenance burden long-term sustainability strategic planning alignment business objectives technical excellence balanced approach prioritizing both immediate deliverables strategic roadmap considerations stakeholder expectations satisfaction metrics tracking progress measuring success indicators defining clear accountability ownership responsibilities distributed appropriately throughout organization structure encouraging innovation creativity while maintaining operational stability reliability predictability essential mission-critical systems requiring high availability resilience graceful degradation capabilities.
