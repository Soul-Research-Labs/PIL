# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in ZASEON, please report it responsibly.

### Preferred Method

**Email:** security@zaseon.io

Please include:

1. **Description** of the vulnerability
2. **Steps to reproduce** (if applicable)
3. **Affected component** (engine, web, fuzzer, API, etc.)
4. **Potential impact** assessment
5. **Suggested fix** (if you have one)

### What to Expect

- **Acknowledgment** within 48 hours
- **Assessment** within 7 days
- **Fix timeline** communicated based on severity
- **Credit** in security advisory (if desired)

### Severity Classification

| Severity | Response Time | Examples                              |
| -------- | ------------- | ------------------------------------- |
| Critical | 24 hours      | RCE, auth bypass, data exfiltration   |
| High     | 72 hours      | Privilege escalation, SQL injection   |
| Medium   | 1 week        | XSS, CSRF, information disclosure     |
| Low      | 2 weeks       | Rate limiting bypass, minor info leak |

### Scope

The following are in scope:

- ZASEON API (engine)
- ZASEON Web application (web)
- Authentication and authorization
- Smart contract scanning pipeline
- Soul Protocol fuzzer
- Docker/Kubernetes configurations
- CI/CD pipeline security

### Out of Scope

- Third-party dependencies (report upstream)
- Social engineering attacks
- Physical security
- Denial of service (unless via application logic)

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.2.x   | ✅        |
| < 0.2   | ❌        |

## Security Best Practices for Deployment

1. **Never expose** the engine API directly to the internet without authentication
2. **Rotate** `ZASEON_SECRET_KEY` and API keys regularly
3. **Enable** rate limiting in production
4. **Use** TLS termination at the ingress/load balancer
5. **Restrict** Docker socket access in production
6. **Review** all environment variables before deployment
7. **Enable** structured logging for audit trails
