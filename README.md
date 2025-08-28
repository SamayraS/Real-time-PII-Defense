# Real-time-PII-Defense
FlipkartISCP2025

## Proposed Solution: Express Middleware + Log Sanitizer Module

### 1. Primary Layer: Express Middleware
**Implementation**: A lightweight middleware in the existing Express backend  
- **Location**: Directly in `/api/*` routes within the backend  
- **Function**: Real-time PII detection on request/response payloads  
- **Redaction**: Automatically masks sensitive values before data reaches the database (`analyses`, `sops`, `users`) or leaves via API responses  

### 2. Secondary Layer: Log Sanitizer Module
**Implementation**: A central log-processing module wired into `/api/logs (SSE)` and `/api/logs/recent`  
- **Location**: Inside backend logging pipeline  
- **Function**: Scan log entries for PII before streaming to the Dashboard or storing  
- **Redaction**: Replace sensitive tokens/IDs with safe placeholders before persistence  

## Essentials for Implementation
1. **Express Middleware Hook** (for request/response scanning)  
2. **Centralized Log Processor** (pluggable into existing `/api/logs` flow)  
3. **Configurable PII Rules** (JSON config, updatable by Admin Panel)  

## Advantages
- **Low Latency**: Middleware introduces negligible delay per request  
- **Cost-Effective**: Reuses the existing Express app — no new infrastructure  
- **Comprehensive**: Covers both API traffic and log outputs  
- **Easy Integration**: No need for Kubernetes, API Gateway, or external services  

## Monitoring & Maintenance
- Admin Panel can manage PII redaction rules  
- Metrics on redaction frequency sent to Dashboard  
- Regular updates to detection patterns  
