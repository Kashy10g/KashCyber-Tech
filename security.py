#!/usr/bin/env python3
"""
CypherCore Smart Logic Processor (CLV Architecture)

Purpose:
    - Handle message processing and business logic
    - State machine for conversation management
    - Integration with Meta WhatsApp API for outbound messages
    - Expert error handling with graceful degradation

Convention:
    - All business logic and AI routing happens here
    - Never call external APIs directly from main.py
    - Graceful error handling - never crash on bad data
    - All operations must be traceable via request_id
    - Async-first for high-load resilience

Author: CypherCore Enterprise Team
Version: 1.0.0
License: Proprietary
"""

import logging
import asyncio
import os
from typing import Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

import httpx
from dotenv import load_dotenv

from security import SecurityVault

# Load environment variables
load_dotenv()

# Configure logger for Logic Processor
logger = logging.getLogger("CypherCore.Processor")


# ====================== CUSTOM EXCEPTIONS ======================
class ProcessorException(Exception):
    """Base exception for Processor failures."""
    pass


class ValidationException(ProcessorException):
    """Raised when message validation fails."""
    pass


class MetaAPIException(ProcessorException):
    """Raised when Meta API communication fails."""
    pass


class DataIntegrityException(ProcessorException):
    """Raised when data integrity is compromised."""
    pass


# ====================== ENUMS & DATA CLASSES ======================
class MessageType(str, Enum):
    """Supported WhatsApp message types."""
    TEXT = "text"
    INTERACTIVE = "interactive"
    IMAGE = "image"
    DOCUMENT = "document"
    AUDIO = "audio"
    VIDEO = "video"
    UNKNOWN = "unknown"


@dataclass
class IncomingMessage:
    """
    Structured representation of incoming WhatsApp message.
    Ensures data integrity and type safety.
    """
    request_id: str
    user_phone: str
    message_id: str
    message_type: MessageType
    text_body: str
    timestamp: int
    
    def __post_init__(self):
        """Validate message data on instantiation."""
        if not self.user_phone or not self.request_id:
            raise ValidationException("Missing required message fields: phone or request_id")
        
        if not self.message_id:
            raise ValidationException("Missing message_id - data integrity compromised")


@dataclass
class OutgoingMessage:
    """
    Structured representation of outgoing WhatsApp message.
    Ensures consistency and traceability.
    """
    to_phone: str
    message_text: str
    request_id: str
    retry_count: int = 0
    max_retries: int = 3


# ====================== CORE LOGIC CLASS ======================
class CypherLogic:
    """
    Expert-level message processor and business logic engine.
    
    Responsibilities:
        1. Parse and validate incoming webhook payloads
        2. Extract message data safely (never crash on bad JSON)
        3. Route to appropriate business logic handlers
        4. Send outbound messages via Meta API
        5. Maintain state and conversation context (future: database integration)
        6. Log all operations for audit trail
    
    Design Principles:
        - Graceful degradation (never crash the background task)
        - Async-first (non-blocking I/O)
        - Type-safe (dataclasses, enums)
        - Traceable (request_id in all logs)
        - Resilient (timeouts, retries, exponential backoff)
    """
    
    def __init__(self):
        """
        Initialize Logic Processor with credentials and HTTP client.
        
        Raises:
            RuntimeError: If required environment variables are missing
        """
        self.token: str = os.getenv("WHATSAPP_TOKEN", "").strip()
        self.phone_id: str = os.getenv("PHONE_NUMBER_ID", "").strip()
        self.api_version: str = os.getenv("VERSION", "v20.0").strip()
        
        # Validate credentials at startup
        if not self.token:
            logger.critical("CONFIGURATION ERROR: WHATSAPP_TOKEN not set in environment")
            raise RuntimeError("WHATSAPP_TOKEN environment variable is required")
        
        if not self.phone_id:
            logger.critical("CONFIGURATION ERROR: PHONE_NUMBER_ID not set in environment")
            raise RuntimeError("PHONE_NUMBER_ID environment variable is required")
        
        # Initialize async HTTP client with production settings
        self.http_client: Optional[httpx.AsyncClient] = None
        self._initialize_http_client()
        
        self.security_vault = SecurityVault()
        logger.info("CypherLogic initialized successfully")
    
    def _initialize_http_client(self) -> None:
        """
        Initialize HTTP client with production-grade settings.
        
        Configuration:
            - 10 second timeout (prevents hanging requests)
            - Connection pooling (20 max keepalive, 100 total)
            - HTTP/2 support (faster, more efficient)
            - Automatic retries on transient failures
        """
        try:
            limits = httpx.Limits(
                max_keepalive_connections=20,
                max_connections=100
            )
            
            self.http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(10.0),
                limits=limits,
                http2=True
            )
            logger.debug("HTTP client initialized with production settings")
        except Exception as e:
            logger.error(f"Failed to initialize HTTP client: {str(e)}", exc_info=True)
            raise RuntimeError(f"HTTP client initialization failed: {str(e)}")
    
    async def handle_event(self, data: Dict[str, Any]) -> Dict[str, str]:
        """
        Expert-level event handler - main entry point for all webhook events.
        
        Process Flow:
            1. Extract request_id for tracing
            2. Validate payload structure (Meta webhook format)
            3. Safely extract message data (graceful degradation)
            4. Route to appropriate handler
            5. Log all operations for audit trail
            6. Never crash - always return status dict
        
        Args:
            data: Parsed JSON payload from Meta webhook
        
        Returns:
            Dict with processing status (always returns, never raises)
        
        Security Notes:
            - Handles malformed JSON gracefully
            - Validates all extracted data
            - Logs security-relevant events
            - No sensitive data in response
        """
        request_id: str = data.get("request_id", "unknown")
        
        try:
            logger.info(f"[{request_id}] Processing webhook event", extra={"step": "entry"})
            
            # Validate payload structure first (fail fast)
            if not self.security_vault.validate_json_payload(data):
                logger.warning(
                    f"[{request_id}] Invalid payload structure",
                    extra={"event_type": "INVALID_STRUCTURE"}
                )
                return {"status": "invalid_payload_structure"}
            
            # Safe deep extraction from Meta webhook format
            try:
                entry = data.get("entry", [{}])[0]
                changes = entry.get("changes", [{}])[0]
                value = changes.get("value", {})
                messages = value.get("messages", [])
                
                if not messages:
                    logger.debug(
                        f"[{request_id}] No messages in webhook (status update or other event)",
                        extra={"event_type": "NO_MESSAGES"}
                    )
                    return {"status": "ignored_non_message_event"}
                
                msg = messages[0]
                
            except (IndexError, KeyError, TypeError) as e:
                logger.error(
                    f"[{request_id}] Failed to extract message from webhook: {str(e)}",
                    exc_info=True,
                    extra={"event_type": "EXTRACTION_ERROR"}
                )
                return {"status": "failed_to_extract_message"}
            
            # Extract and validate message fields
            user_phone: str = msg.get("from", "").strip()
            message_id: str = msg.get("id", "").strip()
            message_type: str = msg.get("type", "unknown").strip()
            timestamp: int = msg.get("timestamp", 0)
            
            # Validate phone number
            if not self.security_vault.validate_phone_number(user_phone):
                logger.warning(
                    f"[{request_id}] Invalid phone number format: {user_phone}",
                    extra={"event_type": "INVALID_PHONE"}
                )
                return {"status": "invalid_phone_number"}
            
            # Extract text body based on message type
            if message_type == "text":
                raw_text = msg.get("text", {}).get("body", "").strip()
            else:
                raw_text = f"[{message_type.upper()} MESSAGE]"
            
            # Sanitize input (prevents injection attacks)
            text_body = self.security_vault.sanitize_input(raw_text, max_length=2000)
            if not text_body:
                logger.warning(
                    f"[{request_id}] Input sanitization resulted in empty text",
                    extra={"event_type": "EMPTY_TEXT_AFTER_SANITIZATION"}
                )
                return {"status": "empty_message_text"}
            
            # Create structured message object (type-safe)
            incoming_msg = IncomingMessage(
                request_id=request_id,
                user_phone=user_phone,
                message_id=message_id,
                message_type=MessageType(message_type) if message_type in MessageType.__members__ else MessageType.UNKNOWN,
                text_body=text_body,
                timestamp=timestamp
            )
            
            logger.info(
                f"[{request_id}] Valid message extracted - {incoming_msg.message_type} from {user_phone}",
                extra={"step": "message_extracted", "phone": user_phone}
            )
            
            # Route to appropriate handler (business logic)
            response_text = await self.generate_smart_response(incoming_msg)
            
            # Send response (fire and forget in background, but still logged)
            await self.send_message(
                OutgoingMessage(
                    to_phone=user_phone,
                    message_text=response_text,
                    request_id=request_id
                )
            )
            
            logger.info(
                f"[{request_id}] Event processed successfully",
                extra={"step": "complete", "status": "success"}
            )
            return {"status": "processed_successfully"}
        
        except ValidationException as e:
            logger.warning(
                f"[{request_id}] Validation error: {str(e)}",
                extra={"event_type": "VALIDATION_ERROR"}
            )
            return {"status": "validation_error"}
        
        except Exception as e:
            # Catch-all for unexpected errors (never crash)
            logger.error(
                f"[{request_id}] CRITICAL PROCESSING ERROR: {str(e)}",
                exc_info=True,
                extra={"event_type": "UNHANDLED_EXCEPTION"}
            )
            return {"status": "error_graceful_degradation"}
    
    async def generate_smart_response(self, msg: IncomingMessage) -> str:
        """
        Generate smart response based on message content.
        
        Current Implementation:
            - Simple keyword matching (placeholder for AI/ML integration)
            - Ready for state machine, database lookup, LLM integration
        
        Future Integration Points:
            - Database user session lookup
            - Conversation state machine
            - LLM/AI model integration (like Meta AI or MTN Zigi)
            - Rule engine for business logic
            - External API calls to microservices
        
        Args:
            msg: Structured incoming message
        
        Returns:
            Response text to send to user
        """
        try:
            text_lower = msg.text_body.lower().strip()
            
            # Placeholder keyword responses
            if any(greeting in text_lower for greeting in ["hello", "hi", "hey", "start"]):
                return (
                    "👋 Hello! I'm CypherCore, your secure AI assistant.\n\n"
                    "I'm here to help you with:\n"
                    "• Information & answers\n"
                    "• Business support\n"
                    "• Account management\n\n"
                    "What can I help you with today?"
                )
            
            elif any(bye in text_lower for bye in ["bye", "goodbye", "see you", "quit"]):
                return "Goodbye! Have a great day. Feel free to reach out anytime. 👋"
            
            elif any(help_word in text_lower for help_word in ["help", "support", "issue"]):
                return (
                    "I'd be happy to help! 🤝\n\n"
                    "Please describe your issue and I'll do my best to assist you.\n"
                    "Response time: Usually within 5 minutes."
                )
            
            else:
                # Default response (ready for AI/LLM integration)
                return (
                    f"Thanks for your message! I received: \"{msg.text_body[:100]}\"\n\n"
                    "I'm processing your request securely. "
                    "Advanced AI features coming soon! 🚀"
                )
        
        except Exception as e:
            logger.error(
                f"[{msg.request_id}] Error generating response: {str(e)}",
                exc_info=True
            )
            return "I encountered a temporary issue. Please try again shortly."
    
    async def send_message(self, outgoing: OutgoingMessage) -> Dict[str, Any]:
        """
        Send message to user via Meta WhatsApp API with retry logic.
        
        Features:
            - Exponential backoff retry on transient failures
            - Timeout protection (10 seconds)
            - Detailed error logging
            - Graceful handling of API errors
        
        Args:
            outgoing: Message to send (to_phone, text, request_id)
        
        Returns:
            Dict with response from Meta API or error status
        """
        if not self.http_client:
            logger.error(
                f"[{outgoing.request_id}] HTTP client not initialized",
                extra={"event_type": "NO_HTTP_CLIENT"}
            )
            return {"status": "client_not_initialized", "success": False}
        
        url = f"https://graph.facebook.com/{self.api_version}/{self.phone_id}/messages"
        
        payload = {
            "messaging_product": "whatsapp",
            "to": outgoing.to_phone,
            "type": "text",
            "text": {"body": outgoing.message_text}
        }
        
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        retry_delay = 1  # Start with 1 second
        
        while outgoing.retry_count < outgoing.max_retries:
            try:
                logger.debug(
                    f"[{outgoing.request_id}] Sending message to {outgoing.to_phone} "
                    f"(attempt {outgoing.retry_count + 1}/{outgoing.max_retries})",
                    extra={"event_type": "SEND_ATTEMPT"}
                )
                
                response = await self.http_client.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=10.0
                )
                
                # Check for success
                if response.status_code in [200, 201]:
                    logger.info(
                        f"[{outgoing.request_id}] Message sent successfully to {outgoing.to_phone}",
                        extra={"event_type": "MESSAGE_SENT", "status_code": response.status_code}
                    )
                    return {
                        "status": "sent",
                        "success": True,
                        "response": response.json()
                    }
                
                # Handle API errors
                elif response.status_code in [429, 500, 502, 503, 504]:
                    # Transient errors - retry with backoff
                    outgoing.retry_count += 1
                    
                    if outgoing.retry_count < outgoing.max_retries:
                        logger.warning(
                            f"[{outgoing.request_id}] Transient API error {response.status_code} - "
                            f"retrying in {retry_delay}s",
                            extra={
                                "event_type": "TRANSIENT_ERROR",
                                "status_code": response.status_code,
                                "retry_count": outgoing.retry_count
                            }
                        )
                        await asyncio.sleep(retry_delay)
                        retry_delay *= 2  # Exponential backoff
                        continue
                    else:
                        logger.error(
                            f"[{outgoing.request_id}] Max retries exhausted for {outgoing.to_phone}",
                            extra={"event_type": "MAX_RETRIES_EXHAUSTED", "status_code": response.status_code}
                        )
                        return {
                            "status": "failed_max_retries",
                            "success": False,
                            "status_code": response.status_code
                        }
                
                else:
                    # Permanent error - don't retry
                    logger.error(
                        f"[{outgoing.request_id}] API error {response.status_code}: {response.text}",
                        extra={
                            "event_type": "PERMANENT_ERROR",
                            "status_code": response.status_code
                        }
                    )
                    return {
                        "status": "api_error",
                        "success": False,
                        "status_code": response.status_code,
                        "error": response.text[:200]
                    }
            
            except asyncio.TimeoutError:
                outgoing.retry_count += 1
                
                if outgoing.retry_count < outgoing.max_retries:
                    logger.warning(
                        f"[{outgoing.request_id}] Request timeout - retrying in {retry_delay}s",
                        extra={
                            "event_type": "TIMEOUT",
                            "retry_count": outgoing.retry_count
                        }
                    )
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2
                    continue
                else:
                    logger.error(
                        f"[{outgoing.request_id}] Timeout max retries exhausted",
                        extra={"event_type": "TIMEOUT_MAX_RETRIES"}
                    )
                    return {
                        "status": "timeout_max_retries",
                        "success": False
                    }
            
            except httpx.RequestError as e:
                logger.error(
                    f"[{outgoing.request_id}] Network error: {str(e)}",
                    exc_info=True,
                    extra={"event_type": "NETWORK_ERROR"}
                )
                return {
                    "status": "network_error",
                    "success": False
                }
            
            except Exception as e:
                logger.error(
                    f"[{outgoing.request_id}] Unexpected error sending message: {str(e)}",
                    exc_info=True,
                    extra={"event_type": "UNEXPECTED_ERROR"}
                )
                return {
                    "status": "unexpected_error",
                    "success": False
                }
        
        return {"status": "send_failed", "success": False}
    
    async def close(self) -> None:
        """
        Gracefully close HTTP client and cleanup resources.
        Called during application shutdown.
        """
        if self.http_client:
            try:
                await self.http_client.aclose()
                logger.info("HTTP client closed successfully")
            except Exception as e:
                logger.error(f"Error closing HTTP client: {str(e)}", exc_info=True)
