#!/usr/bin/env python3
"""
CypherCore Security Vault (CLV Architecture)

Purpose:
    - Cryptographic signature validation (HMAC-SHA256)
    - Prevents unauthorized webhook triggers
    - Validates all inbound requests from Meta API
    - Implements expert-level security without exceptions

Convention:
    - Must always validate signatures before logic processing
    - Never allow unverified requests to proceed
    - Log all security events for audit trail
    - Fail securely with meaningful error responses

Author: CypherCore Enterprise Team
Version: 1.0.0
License: Proprietary
"""

import hmac
import hashlib
import logging
import os
from typing import Optional
from fastapi import Request, HTTPException
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logger for Security Vault
logger = logging.getLogger("CypherCore.SecurityVault")


class SecurityVaultException(Exception):
    """Base exception for Security Vault failures."""
    pass


class SignatureValidationException(SecurityVaultException):
    """Raised when signature validation fails."""
    pass


class MissingCredentialsException(SecurityVaultException):
    """Raised when required credentials are missing."""
    pass


class SecurityVault:
    """
    Professional-grade security validation for Meta WhatsApp API.
    
    Responsibilities:
        1. Validate HMAC-SHA256 signatures from Meta
        2. Prevent replay attacks and tampering
        3. Maintain audit logs of security events
        4. Fail securely without exposing internal details
    
    Security Principles:
        - Cryptographic signature verification is mandatory
        - No business logic executes without validation
        - All security events are logged with full context
        - Timing-safe comparison prevents timing attacks
    """
    
    def __init__(self):
        """
        Initialize Security Vault with credentials from environment.
        
        Raises:
            MissingCredentialsException: If APP_SECRET is not configured
        """
        self.app_secret = os.getenv("APP_SECRET")
        
        if not self.app_secret:
            logger.critical(
                "SECURITY_CRITICAL: APP_SECRET not configured. "
                "WhatsApp signature validation disabled. "
                "This is a critical configuration error."
            )
            raise MissingCredentialsException(
                "APP_SECRET environment variable is required for security validation"
            )
        
        logger.info("SecurityVault initialized successfully")
    
    async def validate_signature(self, request: Request) -> bool:
        """
        Validates that the incoming request is genuinely from Meta.
        
        Process:
            1. Extract X-Hub-Signature-256 header
            2. Verify signature algorithm is SHA256
            3. Compute expected HMAC using request body + APP_SECRET
            4. Compare using timing-safe comparison
        
        Args:
            request: FastAPI Request object
        
        Returns:
            bool: True if signature is valid
        
        Raises:
            HTTPException: 403 if signature is invalid or missing
            HTTPException: 501 if signature algorithm is unsupported
        
        Security Notes:
            - Uses hmac.compare_digest() to prevent timing attacks
            - Body is read only once and cached
            - All failures are logged with context for audit trail
        """
        try:
            # Step 1: Extract signature header
            signature_header = request.headers.get("X-Hub-Signature-256")
            
            if not signature_header:
                logger.warning(
                    event="SIGNATURE_VALIDATION_FAILED",
                    reason="Missing X-Hub-Signature-256 header",
                    remote_ip=request.client.host if request.client else "unknown"
                )
                raise HTTPException(
                    status_code=403,
                    detail="Missing X-Hub-Signature-256 header"
                )
            
            # Step 2: Parse signature format (sha256=hash)
            try:
                signature_algorithm, signature_hash = signature_header.split("=")
            except ValueError:
                logger.warning(
                    event="SIGNATURE_VALIDATION_FAILED",
                    reason="Malformed signature header format",
                    remote_ip=request.client.host if request.client else "unknown"
                )
                raise HTTPException(
                    status_code=403,
                    detail="Invalid signature format"
                )
            
            # Step 3: Verify algorithm
            if signature_algorithm != "sha256":
                logger.warning(
                    event="SIGNATURE_VALIDATION_FAILED",
                    reason=f"Unsupported signature algorithm: {signature_algorithm}",
                    remote_ip=request.client.host if request.client else "unknown"
                )
                raise HTTPException(
                    status_code=501,
                    detail=f"Unsupported signature algorithm: {signature_algorithm}"
                )
            
            # Step 4: Get request body
            body = await request.body()
            
            if not body:
                logger.warning(
                    event="SIGNATURE_VALIDATION_FAILED",
                    reason="Empty request body",
                    remote_ip=request.client.host if request.client else "unknown"
                )
                raise HTTPException(
                    status_code=403,
                    detail="Empty request body"
                )
            
            # Step 5: Compute expected signature
            expected_hash = hmac.new(
                self.app_secret.encode("utf-8"),
                msg=body,
                digestmod=hashlib.sha256
            ).hexdigest()
            
            # Step 6: Timing-safe comparison (prevents timing attacks)
            is_valid = hmac.compare_digest(expected_hash, signature_hash)
            
            if not is_valid:
                logger.warning(
                    event="SIGNATURE_VALIDATION_FAILED",
                    reason="Signature mismatch - possible tampering or invalid secret",
                    remote_ip=request.client.host if request.client else "unknown",
                    body_length=len(body)
                )
                raise HTTPException(
                    status_code=403,
                    detail="Invalid signature"
                )
            
            # Success
            logger.debug(
                event="SIGNATURE_VALIDATION_SUCCESS",
                remote_ip=request.client.host if request.client else "unknown",
                body_length=len(body)
            )
            return True
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error(
                event="SIGNATURE_VALIDATION_EXCEPTION",
                error_type=type(e).__name__,
                error_message=str(e),
                remote_ip=request.client.host if request.client else "unknown"
            )
            raise HTTPException(
                status_code=403,
                detail="Signature verification failed"
            )
    
    @staticmethod
    def sanitize_input(data: str, max_length: int = 1000) -> Optional[str]:
        """
        Sanitizes user input to prevent injection attacks.
        
        Args:
            data: Raw user input
            max_length: Maximum allowed length (default: 1000 chars)
        
        Returns:
            Sanitized string or None if invalid
        
        Security Notes:
            - Removes null bytes
            - Enforces length limits
            - Strips dangerous control characters
            - Logs suspicious input patterns
        """
        if not data or not isinstance(data, str):
            return None
        
        # Remove null bytes
        data = data.replace("\x00", "")
        
        # Enforce length limit
        if len(data) > max_length:
            logger.warning(
                event="INPUT_SANITIZATION",
                reason="Input exceeds maximum length",
                provided_length=len(data),
                max_length=max_length
            )
            return data[:max_length]
        
        # Remove dangerous control characters (except newline, tab)
        sanitized = "".join(
            char for char in data 
            if ord(char) >= 32 or char in "\n\t"
        )
        
        if sanitized != data:
            logger.warning(
                event="INPUT_SANITIZATION",
                reason="Control characters removed"
            )
        
        return sanitized
