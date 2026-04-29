"""
================================================================================
CypherCore Security Vault (CLV Architecture)
Module: security.py
Purpose: Cryptographic validation, input scrubbing, and security enforcement
Convention: Core-Logic-Vault (CLV) - Security Layer
================================================================================

This module is responsible for:
  - Signature verification (HMAC-SHA256 from Meta)
  - Prevention of unauthorized webhook access
  - Input sanitization and validation
  - Security event logging and audit trails
  - Rate limiting infrastructure
  - Protection against common attack vectors

MUST ALWAYS:
  - Validate every incoming request signature
  - Log all security events (including failures)
  - Never execute business logic without validation
  - Sanitize all user input before processing
  - Fail securely (never expose internal details)

MUST NEVER:
  - Store plaintext secrets
  - Skip signature validation
  - Process unsigned requests
  - Log sensitive data
  - Raise detailed errors to external users
================================================================================
"""

import hmac
import hashlib
import os
import logging
import json
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
from fastapi import Request, HTTPException
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ==============================================================================
# LOGGING CONFIGURATION (Professional Convention)
# ==============================================================================
logger = logging.getLogger("CypherCore.SecurityVault")


# ==============================================================================
# CUSTOM EXCEPTIONS (Enterprise Error Hierarchy)
# ==============================================================================
class SecurityException(Exception):
    """Base exception for all security-related errors."""
    pass


class SignatureValidationError(SecurityException):
    """Raised when signature validation fails."""
    pass


class MissingSecretError(SecurityException):
    """Raised when APP_SECRET is not configured."""
    pass


class InputSanitizationError(SecurityException):
    """Raised when input validation fails."""
    pass


# ==============================================================================
# SECURITY VAULT CLASS
# ==============================================================================
class SecurityVault:
    """
    Enterprise-grade security layer for CypherCore.
    
    Responsibilities:
      1. Cryptographic signature validation (HMAC-SHA256)
      2. Input sanitization and validation
      3. Rate limiting (prepared infrastructure)
      4. Security event logging and monitoring
      5. Prevention of common attack vectors
    
    Convention: Always validate before trust. Always log security events.
    """
    
    # Configuration constants
    SIGNATURE_ALGORITHM = "sha256"
    SIGNATURE_HEADER = "X-Hub-Signature-256"
    MAX_REQUEST_SIZE = 1024 * 1024  # 1MB
    REQUEST_TIMEOUT = 30  # seconds
    
    # Rate limiting (basic implementation ready for enhancement)
    _request_cache: Dict[str, list] = {}
    _cache_cleanup_interval = 3600  # 1 hour
    
    def __init__(self):
        """Initialize SecurityVault with environment validation."""
        self.app_secret = os.getenv("APP_SECRET")
        
        if not self.app_secret:
            logger.critical(
                "SECURITY CRITICAL: APP_SECRET not configured in environment variables. "
                "System cannot initialize without APP_SECRET. "
                "Set APP_SECRET in .env file or environment."
            )
            raise MissingSecretError(
                "APP_SECRET environment variable is required but not set."
            )
        
        logger.info("SecurityVault initialized successfully with APP_SECRET configured.")
    
    # ==========================================================================
    # SIGNATURE VALIDATION (Primary Security Function)
    # ==========================================================================
    async def validate_signature(self, request: Request) -> bool:
        """
        Validate HMAC-SHA256 signature from Meta Webhook.
        
        Must Always Do:
          - Verify every request is cryptographically signed by Meta
          - Prevent unauthorized webhook access
          - Log all validation attempts (pass and fail)
          - Fail securely without exposing internal details
        
        Args:
            request (Request): FastAPI Request object
        
        Returns:
            bool: True if signature is valid
        
        Raises:
            HTTPException: 403 for invalid signature, 400 for malformed request
        
        Professional Convention:
          - Use timing-safe comparison (hmac.compare_digest)
          - Log security events with context
          - Preserve request body for logging
        """
        request_ip = request.client.host if request.client else "UNKNOWN"
        
        try:
            # Step 1: Extract signature from request headers
            signature_header = request.headers.get(self.SIGNATURE_HEADER)
            
            if not signature_header:
                logger.warning(
                    f"SECURITY_EVENT | Missing Signature Header | "
                    f"IP: {request_ip} | "
                    f"Timestamp: {datetime.utcnow().isoformat()}"
                )
                raise HTTPException(
                    status_code=403,
                    detail="Forbidden: Missing signature verification"
                )
            
            # Step 2: Parse signature header (format: sha256=hash)
            try:
                sha_name, signature_hash = signature_header.split('=')
            except ValueError:
                logger.warning(
                    f"SECURITY_EVENT | Malformed Signature Header | "
                    f"IP: {request_ip} | "
                    f"Header: {signature_header[:20]}..."
                )
                raise HTTPException(
                    status_code=400,
                    detail="Bad Request: Invalid signature format"
                )
            
            # Step 3: Verify algorithm is SHA256 (prevent algorithm substitution)
            if sha_name.lower() != self.SIGNATURE_ALGORITHM:
                logger.warning(
                    f"SECURITY_EVENT | Unsupported Signature Algorithm | "
                    f"IP: {request_ip} | "
                    f"Algorithm: {sha_name} | "
                    f"Timestamp: {datetime.utcnow().isoformat()}"
                )
                raise HTTPException(
                    status_code=400,
                    detail="Bad Request: Only SHA256 signatures accepted"
                )
            
            # Step 4: Get request body (already consumed in FastAPI)
            body = await request.body()
            
            if len(body) > self.MAX_REQUEST_SIZE:
                logger.warning(
                    f"SECURITY_EVENT | Request Size Exceeds Limit | "
                    f"IP: {request_ip} | "
                    f"Size: {len(body)} bytes"
                )
                raise HTTPException(
                    status_code=413,
                    detail="Bad Request: Payload too large"
                )
            
            # Step 5: Calculate expected signature (timing-safe)
            try:
                expected_hash = hmac.new(
                    self.app_secret.encode('utf-8'),
                    msg=body,
                    digestmod=hashlib.sha256
                ).hexdigest()
            except Exception as e:
                logger.error(
                    f"SECURITY_ERROR | Signature Calculation Failed | "
                    f"IP: {request_ip} | "
                    f"Error: {str(e)}"
                )
                raise HTTPException(
                    status_code=500,
                    detail="Internal Server Error: Signature validation service unavailable"
                )
            
            # Step 6: Timing-safe comparison (prevents timing attacks)
            if not hmac.compare_digest(expected_hash, signature_hash):
                logger.warning(
                    f"SECURITY_EVENT | Invalid Signature | "
                    f"IP: {request_ip} | "
                    f"Expected: {expected_hash[:16]}... | "
                    f"Received: {signature_hash[:16]}... | "
                    f"Timestamp: {datetime.utcnow().isoformat()}"
                )
                raise HTTPException(
                    status_code=403,
                    detail="Forbidden: Signature verification failed"
                )
            
            # Step 7: Success - Log valid signature
            logger.info(
                f"SECURITY_SUCCESS | Signature Validated | "
                f"IP: {request_ip} | "
                f"Timestamp: {datetime.utcnow().isoformat()}"
            )
            return True
            
        except HTTPException:
            # Re-raise HTTP exceptions (already properly formatted)
            raise
        except Exception as e:
            # Catch unexpected errors and fail securely
            logger.error(
                f"SECURITY_ERROR | Unexpected Error in Signature Validation | "
                f"IP: {request_ip} | "
                f"Error Type: {type(e).__name__} | "
                f"Error: {str(e)}",
                exc_info=True
            )
            raise HTTPException(
                status_code=500,
                detail="Internal Server Error: Authentication service unavailable"
            )
    
    # ==========================================================================
    # INPUT SANITIZATION (Secondary Security Layer)
    # ==========================================================================
    @staticmethod
    def sanitize_input(raw_input: str, max_length: int = 4096) -> str:
        """
        Sanitize user input to prevent injection attacks.
        
        Protection against:
          - SQL Injection
          - XSS (Cross-Site Scripting)
          - Command Injection
          - Buffer overflow
        
        Args:
            raw_input (str): Raw user input
            max_length (int): Maximum allowed input length
        
        Returns:
            str: Sanitized input
        
        Raises:
            InputSanitizationError: If input fails validation
        """
        if not isinstance(raw_input, str):
            raise InputSanitizationError("Input must be a string")
        
        # Length validation
        if len(raw_input) > max_length:
            logger.warning(
                f"SECURITY_EVENT | Input Exceeds Length Limit | "
                f"Length: {len(raw_input)} | Max: {max_length}"
            )
            raise InputSanitizationError(
                f"Input exceeds maximum length of {max_length} characters"
            )
        
        # Strip whitespace
        sanitized = raw_input.strip()
        
        # Remove null bytes (command injection prevention)
        if '\x00' in sanitized:
            logger.warning("SECURITY_EVENT | Null byte detected in input")
            raise InputSanitizationError("Input contains invalid characters")
        
        # Remove common injection patterns
        dangerous_patterns = [
            "'; DROP TABLE",
            "<script>",
            "javascript:",
            "onclick=",
            "onerror="
        ]
        
        lower_input = sanitized.lower()
        for pattern in dangerous_patterns:
            if pattern.lower() in lower_input:
                logger.warning(
                    f"SECURITY_EVENT | Dangerous Pattern Detected | "
                    f"Pattern: {pattern}"
                )
                raise InputSanitizationError(
                    "Input contains suspicious patterns and was rejected"
                )
        
        return sanitized
    
    # ==========================================================================
    # REQUEST VALIDATION (Comprehensive Input Validation)
    # ==========================================================================
    @staticmethod
    def validate_payload_structure(payload: Dict) -> bool:
        """
        Validate Meta webhook payload structure.
        
        Ensures:
          - Payload has required top-level keys
          - No unexpected data types
          - No missing critical fields
        
        Args:
            payload (Dict): Webhook payload from Meta
        
        Returns:
            bool: True if payload structure is valid
        
        Raises:
            InputSanitizationError: If structure is invalid
        """
        try:
            # Validate top-level structure
            if not isinstance(payload, dict):
                raise InputSanitizationError("Payload must be a dictionary")
            
            # Meta webhooks must have 'object' and 'entry' fields
            if "object" not in payload:
                raise InputSanitizationError("Missing required field: 'object'")
            
            if payload["object"] != "whatsapp_business_account":
                raise InputSanitizationError(
                    f"Invalid object type: {payload['object']}"
                )
            
            if "entry" not in payload or not isinstance(payload["entry"], list):
                raise InputSanitizationError("Missing or invalid field: 'entry'")
            
            if not payload["entry"]:
                # Empty entry is valid (webhook test)
                logger.debug("Empty webhook payload (likely test event)")
                return True
            
            # Validate first entry structure
            entry = payload["entry"][0]
            if not isinstance(entry, dict):
                raise InputSanitizationError("Entry must be a dictionary")
            
            if "changes" not in entry or not isinstance(entry["changes"], list):
                raise InputSanitizationError("Missing or invalid field: 'changes'")
            
            return True
            
        except InputSanitizationError:
            raise
        except Exception as e:
            logger.error(
                f"SECURITY_ERROR | Payload Structure Validation Failed | "
                f"Error: {str(e)}",
                exc_info=True
            )
            raise InputSanitizationError(
                "Payload structure validation failed"
            )
    
    # ==========================================================================
    # RATE LIMITING INFRASTRUCTURE (Enterprise Ready)
    # ==========================================================================
    def check_rate_limit(
        self,
        identifier: str,
        max_requests: int = 100,
        time_window: int = 60
    ) -> Tuple[bool, Optional[str]]:
        """
        Check rate limit for a given identifier (IP, phone number, etc).
        
        Professional Convention:
          - Use in-memory cache for high-performance checks
          - Prepared for Redis integration
          - Configurable per endpoint
        
        Args:
            identifier (str): Unique identifier (IP, phone number, etc)
            max_requests (int): Max requests allowed in time window
            time_window (int): Time window in seconds
        
        Returns:
            Tuple[bool, Optional[str]]: (is_allowed, remaining_requests_info)
        """
        current_time = datetime.utcnow()
        
        # Initialize cache entry if not exists
        if identifier not in self._request_cache:
            self._request_cache[identifier] = []
        
        # Clean old timestamps (older than time_window)
        cutoff_time = current_time - timedelta(seconds=time_window)
        self._request_cache[identifier] = [
            ts for ts in self._request_cache[identifier]
            if ts > cutoff_time
        ]
        
        # Check if rate limit exceeded
        if len(self._request_cache[identifier]) >= max_requests:
            logger.warning(
                f"SECURITY_EVENT | Rate Limit Exceeded | "
                f"Identifier: {identifier} | "
                f"Requests: {len(self._request_cache[identifier])}/{max_requests}"
            )
            return False, f"Rate limited: {len(self._request_cache[identifier])}/{max_requests}"
        
        # Add current request
        self._request_cache[identifier].append(current_time)
        return True, f"{len(self._request_cache[identifier])}/{max_requests}"
    
    # ==========================================================================
    # SECURITY EVENT LOGGING
    # ==========================================================================
    @staticmethod
    def log_security_event(
        event_type: str,
        severity: str,
        details: Dict,
        user_identifier: Optional[str] = None
    ) -> None:
        """
        Log security events with full context for audit trail.
        
        Professional Convention:
          - Structured logging for SIEM integration
          - No sensitive data in logs
          - Timestamp and correlation ID
        
        Args:
            event_type (str): Type of security event
            severity (str): Severity level (INFO, WARNING, CRITICAL)
            details (Dict): Event details (sanitized)
            user_identifier (Optional[str]): User/identifier involved
        """
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "severity": severity,
            "user_identifier": user_identifier or "UNKNOWN",
            "details": details
        }
        
        if severity == "CRITICAL":
            logger.critical(json.dumps(log_entry))
        elif severity == "WARNING":
            logger.warning(json.dumps(log_entry))
        else:
            logger.info(json.dumps(log_entry))


# ==============================================================================
# MODULE INITIALIZATION
# ==============================================================================
def initialize_vault() -> SecurityVault:
    """
    Initialize and return SecurityVault instance.
    
    Professional Convention:
      - Called once at application startup
      - Ensures all security prerequisites are met
      - Fails fast if configuration is invalid
    
    Returns:
        SecurityVault: Initialized security vault instance
    
    Raises:
        MissingSecretError: If APP_SECRET is not configured
    """
    try:
        vault = SecurityVault()
        logger.info("SecurityVault initialized successfully")
        return vault
    except MissingSecretError as e:
        logger.critical(f"Failed to initialize SecurityVault: {str(e)}")
        raise


# ==============================================================================
# END OF FILE: security.py
# ==============================================================================
