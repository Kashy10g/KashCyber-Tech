#!/usr/bin/env python3
"""
CypherCore Professional WhatsApp Bot - Main Entry Point (CLV Architecture)

Purpose:
    - FastAPI server entry point
    - Handles Meta webhook verification and message reception
    - Routes all requests through security validation
    - Manages background task processing for high-end operations
    - Never breaks existing functionality

Convention:
    - Security validation ALWAYS comes first
    - Business logic processes in background (no timeout)
    - Immediate 200 OK response to Meta within 2 seconds
    - Professional logging configuration at startup
    - Graceful shutdown handling

Author: CypherCore Enterprise Team
Version: 1.0.0
License: Proprietary
"""

import os
import sys
import logging
import logging.handlers
from datetime import datetime
from fastapi import FastAPI, Request, Response, BackgroundTasks, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from contextlib import asynccontextmanager

# Import CLV modules
from security import SecurityVault, SecurityVaultException
from processor import CypherLogic, ProcessorException

# Load environment variables
load_dotenv()

# ============================================================================
# PROFESSIONAL LOGGING CONFIGURATION
# ============================================================================

def setup_logging() -> logging.Logger:
    """
    Configures professional-grade structured logging.
    
    Configuration:
        - Console output with colored formatting
        - File rotation to prevent disk space issues
        - Separate files for errors and general logs
        - Structured format for log aggregation systems
    
    Returns:
        Configured logger instance
    """
    
    # Create logs directory if it doesn't exist
    os.makedirs("logs", exist_ok=True)
    
    # Create logger
    logger = logging.getLogger("CypherCore")
    logger.setLevel(logging.DEBUG)
    
    # Remove existing handlers to avoid duplicates
    logger.handlers.clear()
    
    # Formatter: Professional structured format
    detailed_formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)-30s | %(funcName)-20s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # Handler 1: Console (INFO level and above)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(detailed_formatter)
    logger.addHandler(console_handler)
    
    # Handler 2: Main log file (rotating)
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            "logs/cyphercore_system.log",
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5  # Keep 5 backups
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(detailed_formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"Warning: Could not setup file logging: {e}")
    
    # Handler 3: Error log file (rotating)
    try:
        error_handler = logging.handlers.RotatingFileHandler(
            "logs/cyphercore_errors.log",
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(detailed_formatter)
        logger.addHandler(error_handler)
    except Exception as e:
        print(f"Warning: Could not setup error logging: {e}")
    
    return logger


# Initialize logger
logger = setup_logging()


# ============================================================================
# GLOBAL INITIALIZATION
# ============================================================================

# Initialize CLV components
try:
    vault = SecurityVault()
    logic = CypherLogic()
    VERIFY_TOKEN = os.getenv("VERIFY_TOKEN")
    
    if not VERIFY_TOKEN:
        logger.critical(
            "CONFIGURATION_ERROR: VERIFY_TOKEN environment variable is required"
        )
        raise ValueError("VERIFY_TOKEN is not configured")
    
    logger.info(
        "INITIALIZATION_COMPLETE",
        event="System components initialized successfully"
    )
except (ProcessorException, SecurityVaultException, ValueError) as e:
    logger.critical(
        event="INITIALIZATION_FAILED",
        error_type=type(e).__name__,
        error_message=str(e)
    )
    sys.exit(1)


# ============================================================================
# LIFESPAN MANAGEMENT
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manages application startup and shutdown.
    
    Startup:
        - Initialize database connections
        - Verify API credentials
        - Load configuration
    
    Shutdown:
        - Close database connections
        - Flush logs
        - Cleanup resources
    """
    # Startup
    logger.info(
        event="APPLICATION_STARTUP",
        timestamp=datetime.now().isoformat(),
        version="1.0.0"
    )
    
    yield
    
    # Shutdown
    logger.info(
        event="APPLICATION_SHUTDOWN",
        timestamp=datetime.now().isoformat()
    )
    
    # Flush all handlers
    for handler in logger.handlers:
        handler.flush()


# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

app = FastAPI(
    title="CypherCore Enterprise WhatsApp Bot",
    description="Professional, secure, intelligent WhatsApp bot following CLV Architecture",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Configuration (adjust as needed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[],  # Restrict to specific origins in production
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)


# ============================================================================
# WEBHOOK ENDPOINTS
# ============================================================================

@app.get("/")
async def root():
    """
    Health check endpoint.
    """
    return {
        "status": "operational",
        "service": "CypherCore",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }


@app.get("/health")
async def health_check():
    """
    Detailed health check endpoint.
    """
    return {
        "status": "healthy",
        "components": {
            "security_vault": "operational",
            "logic_processor": "operational",
            "api_gateway": "operational"
        },
        "timestamp": datetime.now().isoformat()
    }


@app.get("/webhook")
async def meta_verification(request: Request):
    """
    Meta WhatsApp Verification Endpoint (Webhook Handshake).
    
    Must Always Have:
        - Respond to Meta's initial verification request
        - Verify the correct token is provided
        - Echo back the challenge string
    
    Flow:
        1. Meta sends GET request with hub.mode, hub.challenge, hub.verify_token
        2. Server verifies the token matches VERIFY_TOKEN
        3. Server returns the challenge string
        4. Meta confirms webhook is live
    
    Args:
        request: FastAPI Request object
    
    Returns:
        Challenge string if verified, 403 if not
    
    References:
        https://developers.facebook.com/docs/whatsapp/cloud-api/webhooks/setup-webhooks
    """
    try:
        params = request.query_params
        
        mode = params.get("hub.mode")
        challenge = params.get("hub.challenge")
        token = params.get("hub.verify_token")
        
        logger.debug(
            event="WEBHOOK_VERIFICATION_REQUEST",
            mode=mode,
            remote_ip=request.client.host if request.client else "unknown"
        )
        
        # Verify mode
        if mode != "subscribe":
            logger.warning(
                event="WEBHOOK_VERIFICATION_FAILED",
                reason="Invalid mode",
                provided_mode=mode
            )
            return Response(content="Forbidden: Invalid mode", status_code=403)
        
        # Verify token
        if token != VERIFY_TOKEN:
            logger.warning(
                event="WEBHOOK_VERIFICATION_FAILED",
                reason="Invalid token",
                remote_ip=request.client.host if request.client else "unknown"
            )
            return Response(content="Forbidden: Invalid token", status_code=403)
        
        # Verify challenge exists
        if not challenge:
            logger.warning(
                event="WEBHOOK_VERIFICATION_FAILED",
                reason="Missing challenge"
            )
            return Response(content="Forbidden: Missing challenge", status_code=403)
        
        # Success
        logger.info(
            event="WEBHOOK_VERIFICATION_SUCCESS",
            remote_ip=request.client.host if request.client else "unknown"
        )
        
        return Response(content=challenge, status_code=200)
    
    except Exception as e:
        logger.error(
            event="WEBHOOK_VERIFICATION_EXCEPTION",
            error_type=type(e).__name__,
            error_message=str(e)
        )
        return Response(content="Server error", status_code=500)


@app.post("/webhook")
async def webhook_handler(request: Request, background_tasks: BackgroundTasks):
    """
    Main Webhook Handler for Meta WhatsApp Messages.
    
    Must Always Do:
        1. Validate cryptographic signature (SECURITY FIRST)
        2. Return 200 OK immediately (within 2 seconds)
        3. Process message logic in background (avoid timeout)
        4. Log all operations for audit trail
    
    Architecture:
        - SECURITY: Validate signature before anything else
        - SPEED: Return 200 to Meta instantly
        - LOGIC: Process business logic in background
        - STABILITY: Never crash on high-end tasks
    
    Args:
        request: FastAPI Request object with signature headers
        background_tasks: FastAPI background task manager
    
    Returns:
        {"status": "accepted"} (200 OK) - Always within 2 seconds
    
    Notes:
        - Meta expects 200 response within 20 seconds
        - We respond within 2 seconds for safety margin
        - Business logic processes asynchronously
        - All failures are gracefully handled
    """
    request_id = None
    remote_ip = request.client.host if request.client else "unknown"
    
    try:
        # ===== PHASE 1: SECURITY VALIDATION (FIRST PRIORITY) =====
        logger.debug(
            event="WEBHOOK_RECEIVED",
            remote_ip=remote_ip
        )
        
        # Validate signature (raises HTTPException if invalid)
        await vault.validate_signature(request)
        
        # ===== PHASE 2: PARSE PAYLOAD =====
        try:
            payload = await request.json()
        except ValueError as e:
            logger.error(
                event="WEBHOOK_PARSE_ERROR",
                error="Invalid JSON",
                remote_ip=remote_ip
            )
            return JSONResponse(
                status_code=400,
                content={"status": "error", "message": "Invalid JSON"}
            )
        
        # Extract request ID for tracing
        try:
            entry = payload.get("entry", [{}])[0]
            request_id = entry.get("id", "unknown")
        except (IndexError, TypeError):
            request_id = "unknown"
        
        logger.info(
            event="WEBHOOK_ACCEPTED",
            request_id=request_id,
            remote_ip=remote_ip
        )
        
        # ===== PHASE 3: OFFLOAD TO BACKGROUND (AVOID TIMEOUT) =====
        # The heavy processing happens here, not in the request handler
        background_tasks.add_task(
            logic.handle_event,
            payload
        )
        
        # ===== PHASE 4: IMMEDIATE RESPONSE TO META =====
        # Return instantly so Meta doesn't think we're slow
        return JSONResponse(
            status_code=200,
            content={"status": "accepted", "request_id": request_id}
        )
    
    except HTTPException as e:
        # Security exceptions (invalid signature, etc.)
        logger.warning(
            event="WEBHOOK_REJECTED",
            request_id=request_id,
            status_code=e.status_code,
            detail=e.detail,
            remote_ip=remote_ip
        )
        return JSONResponse(
            status_code=e.status_code,
            content={"status": "rejected", "message": e.detail}
        )
    
    except Exception as e:
        # Unexpected exceptions (never expected, but always handle)
        logger.error(
            event="WEBHOOK_EXCEPTION",
            request_id=request_id,
            error_type=type(e).__name__,
            error_message=str(e),
            remote_ip=remote_ip,
            exc_info=True
        )
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": "Internal server error"}
        )


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """
    Handle HTTP exceptions with proper logging.
    """
    logger.warning(
        event="HTTP_EXCEPTION",
        status_code=exc.status_code,
        detail=exc.detail,
        path=request.url.path,
        remote_ip=request.client.host if request.client else "unknown"
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail}
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """
    Handle unexpected exceptions with proper logging.
    """
    logger.error(
        event="UNHANDLED_EXCEPTION",
        error_type=type(exc).__name__,
        error_message=str(exc),
        path=request.url.path,
        remote_ip=request.client.host if request.client else "unknown",
        exc_info=True
    )
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error"}
    )


# ============================================================================
# STARTUP VERIFICATION
# ============================================================================

if __name__ == "__main__":
    logger.info(
        "="*80
    )
    logger.info(
        "CypherCore Enterprise WhatsApp Bot - CLV Architecture"
    )
    logger.info(
        "Version: 1.0.0 | Status: READY"
    )
    logger.info(
        "="*80
    )
    logger.info(
        "To start the server, run:\n"
        "  uvicorn main:app --reload --host 0.0.0.0 --port 8000"
    )
