# CypherCore CLV Architecture Documentation

## Overview

**CypherCore** is an enterprise-grade WhatsApp bot following the **Core-Logic-Vault (CLV) Architecture** pattern. This architecture ensures:

- 🔒 **Security First**: No business logic executes without cryptographic validation
- ⚡ **High Performance**: Async operations, background processing, sub-2-second responses
- 🛡️ **Stability**: Expert error handling, graceful degradation, never crashes on high-end tasks
- 📊 **Professional**: Structured logging, audit trails, enterprise conventions
- �� **Modular**: Three independent, testable components

---

## Architecture Layers

### 1. **The Security Vault** (`security.py`)

**Responsibility**: Cryptographic validation and input sanitization

**Key Features**:
- HMAC-SHA256 signature verification
- Prevents unauthorized webhook triggers
- Timing-safe comparison (prevents timing attacks)
- Input sanitization (prevents injection attacks)
- Audit logging of all security events

**Never**:
- Allow unverified requests to proceed
- Expose internal security details to attackers
- Process business logic before validation

---

### 2. **The Logic Processor** (`processor.py`)

**Responsibility**: Business logic, state machine, data processing

**Key Features**:
- State machine for user interactions
- Data validation at entry and exit points
- Meta API integration with retry logic
- Expert error handling with graceful degradation
- Connection timeout protection

**Must Always**:
- Validate all inputs before processing
- Log all business operations
- Catch exceptions without crashing
- Provide user-friendly error messages

---

### 3. **The Professional Core** (`main.py`)

**Responsibility**: HTTP server, webhook handling, orchestration

**Key Features**:
- FastAPI-based HTTP server
- Meta webhook verification endpoint
- Message reception and routing
- Background task management
- Professional structured logging

**Must**:
- Validate security BEFORE processing
- Return 200 OK within 2 seconds
- Process logic in background
- Never break existing functionality

---

## Request Flow

```
Meta WhatsApp Server
        |
        v
  [HTTP POST /webhook]
        |
        v
  [1. SECURITY] ← security.py
  Validate signature (HMAC-SHA256)
  Reject if invalid (403 Forbidden)
        |
        v (if valid)
  [2. PARSE] ← main.py
  Extract JSON payload
  Return 200 OK immediately
        |
        v (background task)
  [3. LOGIC] ← processor.py
  Extract message data
  Process business logic
  Send response via Meta API
        |
        v
  [4. LOG]
  All activities logged with context
```

---

## Error Handling Strategy

### Layer 1: Security Vault
```python
If signature invalid:
    → Raise HTTPException(403)
    → Log security event
    → Return to client immediately
    → Never proceed to logic
```

### Layer 2: Logic Processor
```python
If message processing fails:
    → Log error with full context
    → Return graceful error message
    → Don't crash, don't expose internals
    → User receives: "CypherCore is optimizing..."
```

### Layer 3: Core Server
```python
If unexpected exception:
    → Log critical error
    → Return 500 with generic message
    → Maintain server stability
    → Never expose stack traces to client
```

---

## Logging Convention

### Log Format
```
YYYY-MM-DD HH:MM:SS | LEVEL | MODULE | FUNCTION | MESSAGE
```

### Log Levels
- **DEBUG**: Detailed diagnostic information (signature checks, API calls)
- **INFO**: General informational messages (webhook accepted, message processed)
- **WARNING**: Warning messages (invalid token, missing fields, rate limits)
- **ERROR**: Error events (API failures, data corruption)
- **CRITICAL**: Critical failures (configuration errors, system shutdown)

### Log Files
- `logs/cyphercore_system.log`: All logs (rotating, 10 MB)
- `logs/cyphercore_errors.log`: Errors only (rotating, 10 MB)
- Console: INFO and above (real-time monitoring)

---

## Security Checklist

✅ **Signature Validation**
- Always validate HMAC-SHA256 signature
- Use timing-safe comparison
- Log all validation failures

✅ **Input Sanitization**
- Remove null bytes
- Enforce length limits
- Strip dangerous control characters
- Validate data types

✅ **API Security**
- Use Bearer token authentication
- HTTPS only (handled by infrastructure)
- Timeout protection (10 seconds)
- Error messages don't expose internals

✅ **Audit Logging**
- Log all security events
- Include request ID for tracing
- Track IP addresses (when available)
- Never log sensitive data (tokens, secrets)

---

## Configuration

### Environment Variables
```
WHATSAPP_TOKEN=your_token
PHONE_NUMBER_ID=your_phone_id
VERIFY_TOKEN=your_verify_token
APP_SECRET=your_app_secret
VERSION=v20.0
```

See `.env.example` for complete configuration.

---

## Performance Characteristics

**Response Time**: < 2 seconds
- Security validation: ~10ms
- Payload parsing: ~5ms
- Response to Meta: ~50ms
- Background processing: runs asynchronously

**Scalability**:
- Handles multiple concurrent requests
- No blocking I/O in main request handler
- Background tasks can be queued/scaled independently

**Reliability**:
- No single point of failure
- Graceful degradation on API errors
- Automatic retry logic for transient failures
- Comprehensive error logging for troubleshooting

---

## Deployment

### Production Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with production values

# Run server
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Health Checks
```bash
# Simple health check
curl http://localhost:8000/health

# Returns: {"status": "healthy", "components": {...}}
```

### Monitoring
- Monitor `logs/cyphercore_errors.log` for errors
- Watch `/health` endpoint for service status
- Track response times from logs
- Alert on critical events

---

## Testing

### Manual Testing
```bash
# Test webhook verification
curl "http://localhost:8000/webhook?hub.mode=subscribe&hub.verify_token=YOUR_TOKEN&hub.challenge=test123"

# Test with signature (requires valid secret)
curl -X POST http://localhost:8000/webhook \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: sha256=<computed_hash>" \
  -d '{"entry": [...]}'
```

### Integration Testing
- Use Meta's official webhook test tool
- Send test messages from actual WhatsApp account
- Verify responses are received
- Check logs for any errors

---

## Maintenance

### Code Changes
- Always maintain the three-file structure
- Add new features to `processor.py`
- Never break existing endpoints in `main.py`
- Update security features only in `security.py`

### Log Rotation
- Automatic rotation at 10 MB
- Keeps 5 backups of each log type
- Stored in `logs/` directory

### Dependencies
- Review `requirements.txt` quarterly
- Keep security patches updated
- Test updates in staging before production

---

## Troubleshooting

### "Invalid Signature" Errors
- Verify `APP_SECRET` matches Meta dashboard
- Check that request body is not modified
- Ensure HMAC algorithm is SHA256

### "Missing VERIFY_TOKEN" Errors
- Verify webhook setup in Meta dashboard
- Check `VERIFY_TOKEN` matches configuration
- Ensure token is not empty or null

### "Meta API Timeout" Errors
- Check network connectivity
- Verify `WHATSAPP_TOKEN` is still valid
- Check Meta API status dashboard
- Review `PHONE_NUMBER_ID` configuration

---

## Convention Adherence

This architecture **must always**:

1. ✅ Validate security before logic
2. ✅ Respond to Meta within 2 seconds
3. ✅ Process business logic in background
4. ✅ Log all activities for audit
5. ✅ Handle errors gracefully
6. ✅ Maintain three-file structure
7. ✅ Never expose internal details
8. ✅ Never crash on high-end tasks
9. ✅ Never break existing functionality
10. ✅ Always use professional logging

---

## Version History

**v1.0.0** (2026-04-29)
- Initial release
- Core-Logic-Vault architecture
- Expert error handling
- Professional logging
- Security-first design

---

**For support or questions, refer to the Meta WhatsApp API documentation:**
https://developers.facebook.com/docs/whatsapp/cloud-api
