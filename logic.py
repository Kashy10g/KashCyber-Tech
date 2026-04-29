#!/usr/bin/env python3
"""
CypherCore Smart Logic Processor (CLV Architecture)

Purpose:
    - Handle message processing and business logic
    - Stateful conversation session management (per-user, TTL-based)
    - Intent classification and smart routing
    - Integration with Meta WhatsApp API for outbound messages
    - Rate limiting, deduplication, and circuit breaker protection
    - Expert error handling with graceful degradation

Convention (IMMUTABLE - never change without explicit instruction):
    ┌─────────────────────────────────────────────────────────────┐
    │  CYPHERCORE STYLE CONTRACT v1.0                             │
    │                                                             │
    │  1. All public methods are async                            │
    │  2. ALL operations carry request_id in logs                 │
    │  3. Custom exceptions — never raise bare Exception          │
    │  4. Dataclasses for all structured data (no raw dicts)      │
    │  5. Graceful degradation — handle_event NEVER raises        │
    │  6. Every external call has timeout + retry + backoff       │
    │  7. Security-first: sanitize ALL inputs before processing   │
    │  8. Structured logging only (key=value extras)              │
    │  9. Constants at module level, never magic strings inline   │
    │ 10. Single Responsibility: one class = one concern          │
    └─────────────────────────────────────────────────────────────┘

Author: CypherCore Enterprise Team
Version: 2.0.0
License: Proprietary
"""

import asyncio
import logging
import os
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Deque, Dict, Optional, Set

import httpx
from dotenv import load_dotenv

from security import SecurityVault

# ── Environment ───────────────────────────────────────────────────────────────
load_dotenv()

# ── Logger ────────────────────────────────────────────────────────────────────
logger = logging.getLogger("CypherCore.Processor")


# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS  (never use magic strings/numbers inline)
# ══════════════════════════════════════════════════════════════════════════════
class Cfg:
    """Immutable runtime configuration. All tunables live here."""
    # Meta API
    API_BASE              = "https://graph.facebook.com"
    API_TIMEOUT           = 10.0          # seconds per attempt
    MAX_RETRIES           = 3
    RETRY_BASE_DELAY      = 1.0           # seconds (doubles each retry)

    # Message limits
    MAX_INPUT_LENGTH      = 2000          # chars — sanitize input
    MAX_RESPONSE_LENGTH   = 4096          # Meta hard limit
    PREVIEW_LENGTH        = 100           # chars shown in echo preview

    # Session / state
    SESSION_TTL           = 1800          # seconds (30 min inactivity)
    MAX_SESSIONS          = 50_000        # memory ceiling

    # Rate limiting
    RATE_WINDOW           = 60            # seconds
    RATE_MAX_MESSAGES     = 30            # per user per window

    # Deduplication
    DEDUP_WINDOW          = 300           # seconds — discard duplicate msg IDs
    DEDUP_MAX_IDS         = 100_000       # memory ceiling

    # Circuit breaker
    CB_FAILURE_THRESHOLD  = 5            # consecutive failures to open
    CB_RECOVERY_TIMEOUT   = 30.0         # seconds before half-open probe

    # Typing indicator
    TYPING_INDICATOR_MS   = 1500         # milliseconds


# ══════════════════════════════════════════════════════════════════════════════
# CUSTOM EXCEPTIONS  (never raise bare Exception — always typed)
# ══════════════════════════════════════════════════════════════════════════════
class ProcessorException(Exception):
    """Base exception for all Processor failures."""

class ValidationException(ProcessorException):
    """Raised when message validation fails."""

class MetaAPIException(ProcessorException):
    """Raised when Meta API communication fails."""

class DataIntegrityException(ProcessorException):
    """Raised when data integrity is compromised."""

class RateLimitException(ProcessorException):
    """Raised when a user exceeds the rate limit."""

class CircuitOpenException(ProcessorException):
    """Raised when the circuit breaker is open (Meta API unhealthy)."""

class SessionException(ProcessorException):
    """Raised when session operations fail."""


# ══════════════════════════════════════════════════════════════════════════════
# ENUMS
# ══════════════════════════════════════════════════════════════════════════════
class MessageType(str, Enum):
    TEXT       = "text"
    INTERACTIVE = "interactive"
    IMAGE      = "image"
    DOCUMENT   = "document"
    AUDIO      = "audio"
    VIDEO      = "video"
    UNKNOWN    = "unknown"


class ConversationState(str, Enum):
    """Finite state machine states for each user session."""
    NEW          = "new"           # First contact — send welcome
    ACTIVE       = "active"        # Normal conversation in progress
    AWAITING     = "awaiting"      # Bot asked a follow-up question
    RATE_LIMITED = "rate_limited"  # Temporarily throttled


class CircuitState(str, Enum):
    CLOSED    = "closed"     # Healthy — requests flow normally
    OPEN      = "open"       # Unhealthy — fail fast, no requests
    HALF_OPEN = "half_open"  # Probing — single test request allowed


class Intent(str, Enum):
    """Classified intent of the user's message."""
    GREETING    = "greeting"
    FAREWELL    = "farewell"
    HELP        = "help"
    AFFIRMATIVE = "affirmative"
    NEGATIVE    = "negative"
    UNKNOWN     = "unknown"


# ══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES  (type-safe structured data — no raw dicts in business logic)
# ══════════════════════════════════════════════════════════════════════════════
@dataclass
class IncomingMessage:
    """Validated, sanitized, structured representation of a WhatsApp message."""
    request_id:   str
    user_phone:   str
    message_id:   str
    message_type: MessageType
    text_body:    str
    timestamp:    int

    def __post_init__(self):
        if not self.user_phone or not self.request_id:
            raise ValidationException("Missing required fields: user_phone or request_id")
        if not self.message_id:
            raise ValidationException("Missing message_id — data integrity compromised")


@dataclass
class OutgoingMessage:
    """Validated, traceable outgoing WhatsApp message."""
    to_phone:    str
    message_text: str
    request_id:  str
    retry_count: int = 0
    max_retries: int = Cfg.MAX_RETRIES


@dataclass
class UserSession:
    """
    Per-user conversation session. Persisted in-memory (swap for Redis in prod).

    Fields:
        phone:          User's WhatsApp number (primary key)
        state:          Current FSM state
        context:        Arbitrary key-value store for multi-turn state
        last_active:    Unix timestamp — used for TTL expiry
        message_count:  Total messages in this session
    """
    phone:         str
    state:         ConversationState = ConversationState.NEW
    context:       Dict[str, Any]    = field(default_factory=dict)
    last_active:   float             = field(default_factory=time.time)
    message_count: int               = 0

    def touch(self) -> None:
        """Refresh TTL on every interaction."""
        self.last_active = time.time()
        self.message_count += 1

    def is_expired(self) -> bool:
        return (time.time() - self.last_active) > Cfg.SESSION_TTL


@dataclass
class SendResult:
    """Typed return value from send_message — never return raw dicts."""
    success:     bool
    status:      str
    status_code: Optional[int] = None
    meta_data:   Optional[Dict[str, Any]] = None


# ══════════════════════════════════════════════════════════════════════════════
# SUPPORT COMPONENTS  (each has a single responsibility)
# ══════════════════════════════════════════════════════════════════════════════
class SessionStore:
    """
    Thread-safe in-memory session store with TTL eviction.

    Design:
        - O(1) get/set via dict
        - TTL enforced lazily on access + periodic sweep
        - Memory-capped at Cfg.MAX_SESSIONS (evicts oldest on overflow)
    """

    def __init__(self):
        self._store: Dict[str, UserSession] = {}

    def get(self, phone: str) -> UserSession:
        """
        Return existing session or create a new one.
        Always returns a valid, non-expired session.
        """
        session = self._store.get(phone)
        if session is None or session.is_expired():
            session = UserSession(phone=phone)
            self._store[phone] = session
            logger.debug(f"Session created for {phone}", extra={"event": "SESSION_NEW"})
        return session

    def save(self, session: UserSession) -> None:
        """Persist session state after each interaction."""
        if len(self._store) >= Cfg.MAX_SESSIONS:
            self._evict_oldest()
        session.touch()
        self._store[session.phone] = session

    def _evict_oldest(self) -> None:
        """Remove the least-recently-used session when at capacity."""
        if not self._store:
            return
        oldest_phone = min(self._store, key=lambda p: self._store[p].last_active)
        del self._store[oldest_phone]
        logger.warning(
            f"Session evicted for {oldest_phone} (store at capacity)",
            extra={"event": "SESSION_EVICTED"}
        )

    def sweep_expired(self) -> int:
        """Remove all expired sessions. Call periodically."""
        expired = [p for p, s in self._store.items() if s.is_expired()]
        for phone in expired:
            del self._store[phone]
        if expired:
            logger.info(
                f"Swept {len(expired)} expired sessions",
                extra={"event": "SESSION_SWEEP", "count": len(expired)}
            )
        return len(expired)


class RateLimiter:
    """
    Per-user sliding-window rate limiter.

    Design:
        - Sliding window via deque of timestamps
        - O(1) amortized per check
        - No external dependency
    """

    def __init__(self):
        self._windows: Dict[str, Deque[float]] = defaultdict(deque)

    def is_allowed(self, phone: str) -> bool:
        """Return True if user is within rate limit, False otherwise."""
        now = time.time()
        window = self._windows[phone]

        # Evict timestamps outside the window
        while window and window[0] < now - Cfg.RATE_WINDOW:
            window.popleft()

        if len(window) >= Cfg.RATE_MAX_MESSAGES:
            return False

        window.append(now)
        return True


class DeduplicationGuard:
    """
    Prevents processing the same WhatsApp message_id twice.

    Meta sends duplicate webhook deliveries — without this, users receive
    duplicate replies, which is one of the most damaging UX failures.

    Design:
        - Fixed-size set with FIFO eviction via deque
        - O(1) lookup and insert
    """

    def __init__(self):
        self._seen: Set[str] = set()
        self._order: Deque[tuple] = deque()  # (timestamp, message_id)

    def is_duplicate(self, message_id: str) -> bool:
        """Return True if this message_id was already processed."""
        self._evict_old()
        return message_id in self._seen

    def mark_seen(self, message_id: str) -> None:
        """Record that this message_id has been processed."""
        self._evict_old()
        if len(self._seen) >= Cfg.DEDUP_MAX_IDS:
            # Evict oldest to stay under cap
            _, oldest_id = self._order.popleft()
            self._seen.discard(oldest_id)
        self._seen.add(message_id)
        self._order.append((time.time(), message_id))

    def _evict_old(self) -> None:
        cutoff = time.time() - Cfg.DEDUP_WINDOW
        while self._order and self._order[0][0] < cutoff:
            _, old_id = self._order.popleft()
            self._seen.discard(old_id)


class CircuitBreaker:
    """
    Protects the Meta API integration from cascade failures.

    States:
        CLOSED    → Normal. Failures counted.
        OPEN      → Fast-fail. No calls made. Waits recovery timeout.
        HALF_OPEN → One probe allowed. Success → CLOSED. Failure → OPEN.
    """

    def __init__(self):
        self._state:            CircuitState = CircuitState.CLOSED
        self._failure_count:    int          = 0
        self._last_failure_at:  float        = 0.0

    @property
    def is_open(self) -> bool:
        if self._state == CircuitState.OPEN:
            if time.time() - self._last_failure_at >= Cfg.CB_RECOVERY_TIMEOUT:
                self._state = CircuitState.HALF_OPEN
                logger.info("Circuit breaker → HALF_OPEN (probing)", extra={"event": "CB_HALF_OPEN"})
                return False  # Allow one probe
            return True
        return False

    def record_success(self) -> None:
        self._failure_count = 0
        if self._state != CircuitState.CLOSED:
            logger.info("Circuit breaker → CLOSED (recovered)", extra={"event": "CB_CLOSED"})
        self._state = CircuitState.CLOSED

    def record_failure(self) -> None:
        self._failure_count += 1
        self._last_failure_at = time.time()
        if self._failure_count >= Cfg.CB_FAILURE_THRESHOLD:
            if self._state != CircuitState.OPEN:
                logger.error(
                    f"Circuit breaker → OPEN after {self._failure_count} failures",
                    extra={"event": "CB_OPEN", "failures": self._failure_count}
                )
            self._state = CircuitState.OPEN


class IntentClassifier:
    """
    Rule-based intent classifier. Swap internals for ML/LLM without changing callers.

    Design principle: The interface is stable — the implementation can evolve
    from keyword rules → embeddings → LLM without any caller changes.
    """

    _INTENT_MAP: Dict[Intent, tuple] = {
        Intent.GREETING:    ("hello", "hi", "hey", "start", "good morning", "good afternoon",
                             "good evening", "sup", "howdy", "what's up"),
        Intent.FAREWELL:    ("bye", "goodbye", "see you", "quit", "exit", "later", "ciao",
                             "take care", "ttyl", "gtg"),
        Intent.HELP:        ("help", "support", "issue", "problem", "assist", "not working",
                             "broken", "stuck", "confused", "lost"),
        Intent.AFFIRMATIVE: ("yes", "yeah", "yep", "sure", "ok", "okay", "alright",
                             "sounds good", "correct", "right", "confirmed"),
        Intent.NEGATIVE:    ("no", "nope", "nah", "not", "cancel", "stop", "wrong",
                             "incorrect", "disagree"),
    }

    def classify(self, text: str) -> Intent:
        """Classify text into a top-level intent. O(n) over keyword set."""
        lowered = text.lower().strip()
        for intent, keywords in self._INTENT_MAP.items():
            if any(kw in lowered for kw in keywords):
                return intent
        return Intent.UNKNOWN


# ══════════════════════════════════════════════════════════════════════════════
# CORE LOGIC CLASS
# ══════════════════════════════════════════════════════════════════════════════
class CypherLogic:
    """
    Enterprise-grade WhatsApp message processor and business logic engine.

    Responsibilities:
        1.  Parse and validate incoming Meta webhook payloads
        2.  Deduplicate messages (Meta sends duplicate webhooks)
        3.  Rate-limit per user (prevent abuse / DoS)
        4.  Manage per-user conversation sessions (stateful FSM)
        5.  Classify intent and route to handler
        6.  Send typing indicators for natural UX
        7.  Send outbound messages via Meta API (with circuit breaker + retry)
        8.  Log all operations for full audit trail
        9.  Never crash — graceful degradation on every code path
        10. Cleanup resources safely on shutdown

    Design Principles (IMMUTABLE):
        - handle_event() NEVER raises — always returns status dict
        - All external I/O is async (non-blocking)
        - All data is typed (dataclasses, enums) — no raw dicts in logic
        - request_id appears in every log line
        - Security validation before any business logic
        - Circuit breaker protects Meta API dependency
        - Sessions store state — bot is never amnesiac mid-conversation
    """

    def __init__(self):
        """
        Initialize all subsystems. Fail loudly at startup if config is missing —
        better to crash now than fail silently in production.

        Raises:
            RuntimeError: Missing required environment variables.
        """
        self.token:       str = os.getenv("WHATSAPP_TOKEN",    "").strip()
        self.phone_id:    str = os.getenv("PHONE_NUMBER_ID",   "").strip()
        self.api_version: str = os.getenv("VERSION", "v20.0").strip()

        if not self.token:
            logger.critical("CONFIGURATION ERROR: WHATSAPP_TOKEN not set")
            raise RuntimeError("WHATSAPP_TOKEN environment variable is required")

        if not self.phone_id:
            logger.critical("CONFIGURATION ERROR: PHONE_NUMBER_ID not set")
            raise RuntimeError("PHONE_NUMBER_ID environment variable is required")

        # Subsystems — each single-responsibility
        self.security_vault    = SecurityVault()
        self.sessions          = SessionStore()
        self.rate_limiter      = RateLimiter()
        self.dedup_guard       = DeduplicationGuard()
        self.circuit_breaker   = CircuitBreaker()
        self.intent_classifier = IntentClassifier()

        # HTTP client — initialized separately so errors are surfaced clearly
        self.http_client: Optional[httpx.AsyncClient] = None
        self._closed: bool = False
        self._initialize_http_client()

        logger.info("CypherLogic v2.0 initialized successfully", extra={"event": "INIT_OK"})

    # ── HTTP Client ──────────────────────────────────────────────────────

    def _initialize_http_client(self) -> None:
        """
        Initialize async HTTP client with production-grade settings.

        Settings:
            - 10s global timeout — prevents request hangs under load
            - HTTP/2 — multiplexed connections, faster for burst traffic
            - Connection pool — 20 keepalive, 100 total (prevents socket exhaustion)
        """
        try:
            limits = httpx.Limits(max_keepalive_connections=20, max_connections=100)
            self.http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(Cfg.API_TIMEOUT),
                limits=limits,
                http2=True,
            )
            logger.debug("HTTP client initialized", extra={"event": "HTTP_CLIENT_READY"})
        except Exception as exc:
            logger.error(f"HTTP client init failed: {exc}", exc_info=True)
            raise RuntimeError(f"HTTP client initialization failed: {exc}") from exc

    # ── Main Entry Point ─────────────────────────────────────────────────────

    async def handle_event(self, data: Dict[str, Any]) -> Dict[str, str]:
        """
        Primary entry point for ALL incoming Meta webhook events.

        This method NEVER raises. Every code path returns a status dict.
        All processing steps are individually guarded.

        Flow:
            validate payload structure
            → extract message fields
            → validate phone / sanitize input
            → deduplicate message_id
            → rate limit check
            → session lookup / FSM
            → intent classification
            → generate response
            → send typing indicator
            → send message
            → save session

        Args:
            data: Parsed JSON from Meta webhook (may be malformed — handled)

        Returns:
            {"status": "<outcome_code>"}  — always, never raises
        """
        request_id: str = data.get("request_id", "unknown")

        try:
            logger.info(f"[{request_id}] Webhook event received", extra={"step": "ENTRY"})

            # ── 1. Structural validation ──────────────────────────────────
            if not self.security_vault.validate_json_payload(data):
                logger.warning(
                    f"[{request_id}] Invalid payload structure",
                    extra={"event": "INVALID_STRUCTURE"}
                )
                return {"status": "invalid_payload_structure"}

            # ── 2. Extract message fields (safe deep traversal) ───────────
            try:
                entry   = data.get("entry", [{}])[0]
                changes = entry.get("changes", [{}])[0]
                value   = changes.get("value", {})
                messages = value.get("messages", [])

                if not messages:
                    logger.debug(
                        f"[{request_id}] No messages in webhook (status/other event)",
                        extra={"event": "NO_MESSAGES"}
                    )
                    return {"status": "ignored_non_message_event"}

                msg = messages[0]

            except (IndexError, KeyError, TypeError) as exc:
                logger.error(
                    f"[{request_id}] Message extraction failed: {exc}",
                    exc_info=True,
                    extra={"event": "EXTRACTION_ERROR"}
                )
                return {"status": "failed_to_extract_message"}

            # ── 3. Field extraction ───────────────────────────────────────
            user_phone:   str = msg.get("from", "").strip()
            message_id:   str = msg.get("id",   "").strip()
            message_type: str = msg.get("type", "unknown").strip()
            timestamp:    int = int(msg.get("timestamp", 0))

            # ── 4. Phone validation ───────────────────────────────────────
            if not self.security_vault.validate_phone_number(user_phone):
                logger.warning(
                    f"[{request_id}] Invalid phone number: {user_phone}",
                    extra={"event": "INVALID_PHONE"}
                )
                return {"status": "invalid_phone_number"}

            # ── 5. Deduplication ──────────────────────────────────────────
            if self.dedup_guard.is_duplicate(message_id):
                logger.info(
                    f"[{request_id}] Duplicate message_id {message_id} — skipping",
                    extra={"event": "DUPLICATE_MESSAGE", "message_id": message_id}
                )
                return {"status": "duplicate_message_ignored"}

            self.dedup_guard.mark_seen(message_id)

            # ── 6. Rate limiting ──────────────────────────────────────────
            if not self.rate_limiter.is_allowed(user_phone):
                logger.warning(
                    f"[{request_id}] Rate limit exceeded for {user_phone}",
                    extra={"event": "RATE_LIMITED", "phone": user_phone}
                )
                # Notify user once (session tracks this to avoid spam)
                session = self.sessions.get(user_phone)
                if session.state != ConversationState.RATE_LIMITED:
                    session.state = ConversationState.RATE_LIMITED
                    self.sessions.save(session)
                    await self.send_message(OutgoingMessage(
                        to_phone=user_phone,
                        message_text=(
                            "⚠️ You're sending messages too quickly.\n"
                            f"Please wait {Cfg.RATE_WINDOW} seconds and try again."
                        ),
                        request_id=request_id,
                    ))
                return {"status": "rate_limited"}

            # ── 7. Text extraction & sanitization ────────────────────────
            raw_text = (
                msg.get("text", {}).get("body", "").strip()
                if message_type == MessageType.TEXT.value
                else f"[{message_type.upper()} MESSAGE]"
            )

            text_body = self.security_vault.sanitize_input(raw_text, max_length=Cfg.MAX_INPUT_LENGTH)
            if not text_body:
                logger.warning(
                    f"[{request_id}] Empty text after sanitization",
                    extra={"event": "EMPTY_AFTER_SANITIZE"}
                )
                return {"status": "empty_message_text"}

            # ── 8. Build typed message ────────────────────────────────────
            try:
                incoming_msg = IncomingMessage(
                    request_id   = request_id,
                    user_phone   = user_phone,
                    message_id   = message_id,
                    message_type = (
                        MessageType(message_type)
                        if message_type in MessageType.__members__
                        else MessageType.UNKNOWN
                    ),
                    text_body    = text_body,
                    timestamp    = timestamp,
                )
            except ValidationException as exc:
                logger.error(
                    f"[{request_id}] IncomingMessage validation failed: {exc}",
                    extra={"event": "MSG_VALIDATION_FAILED"}
                )
                return {"status": "validation_error"}

            logger.info(
                f"[{request_id}] Message parsed — type={incoming_msg.message_type} from={user_phone}",
                extra={"step": "MESSAGE_READY"}
            )

            # ── 9. Session + FSM ──────────────────────────────────────────
            session = self.sessions.get(user_phone)
            if session.state == ConversationState.RATE_LIMITED:
                session.state = ConversationState.ACTIVE  # Reset after window

            # ── 10. Intent classification ─────────────────────────────────
            intent = self.intent_classifier.classify(incoming_msg.text_body)
            logger.debug(
                f"[{request_id}] Intent classified as {intent}",
                extra={"event": "INTENT", "intent": intent.value}
            )

            # ── 11. Typing indicator (professional UX) ───────────────────
            await self._send_typing_indicator(user_phone, request_id)

            # ── 12. Generate response ─────────────────────────────────────
            response_text = await self.generate_smart_response(
                msg=incoming_msg,
                session=session,
                intent=intent,
            )

            # Enforce Meta's response length limit
            if len(response_text) > Cfg.MAX_RESPONSE_LENGTH:
                response_text = response_text[:Cfg.MAX_RESPONSE_LENGTH - 3] + "..."
                logger.warning(
                    f"[{request_id}] Response truncated to {Cfg.MAX_RESPONSE_LENGTH} chars",
                    extra={"event": "RESPONSE_TRUNCATED"}
                )

            # ── 13. Send message ──────────────────────────────────────────
            result = await self.send_message(OutgoingMessage(
                to_phone     = user_phone,
                message_text = response_text,
                request_id   = request_id,
            ))

            # ── 14. Advance FSM state and persist session ─────────────────
            if session.state == ConversationState.NEW:
                session.state = ConversationState.ACTIVE
            self.sessions.save(session)

            logger.info(
                f"[{request_id}] Event completed — send_success={result.success}",
                extra={"step": "COMPLETE", "send_success": result.success}
            )
            return {"status": "processed_successfully"}

        except ValidationException as exc:
            logger.warning(
                f"[{request_id}] Validation error: {exc}",
                extra={"event": "VALIDATION_ERROR"}
            )
            return {"status": "validation_error"}

        except Exception as exc:
            # Absolute last resort — must never propagate upward
            logger.error(
                f"[{request_id}] UNHANDLED EXCEPTION: {exc}",
                exc_info=True,
                extra={"event": "UNHANDLED_EXCEPTION"}
            )
            return {"status": "error_graceful_degradation"}

    # ── Business Logic / Response Generation ─────────────────────────────────

    async def generate_smart_response(
        self,
        msg:     IncomingMessage,
        session: UserSession,
        intent:  Intent,
    ) -> str:
        """
        Generate contextual response using intent + session state.

        Architecture:
            - Intent-first routing (classified upstream, not re-parsed here)
            - Session state controls response variation (first visit vs returning)
            - Every branch is exception-safe with a fallback
            - Ready for LLM integration: swap `_handle_unknown_intent` body

        Future integration points (drop-in replacements):
            - `_handle_unknown_intent` → call LLM API / RAG pipeline
            - `session.context` → persist to Redis / Postgres for cross-restart state
            - Intent enum → extend with domain-specific intents per business vertical

        Args:
            msg:     Validated incoming message
            session: Current user session (may have context from prior turns)
            intent:  Pre-classified intent

        Returns:
            Response string (always, never raises)
        """
        try:
            is_first_visit = session.message_count <= 1

            handlers = {
                Intent.GREETING:    self._handle_greeting,
                Intent.FAREWELL:    self._handle_farewell,
                Intent.HELP:        self._handle_help,
                Intent.AFFIRMATIVE: self._handle_affirmative,
                Intent.NEGATIVE:    self._handle_negative,
                Intent.UNKNOWN:     self._handle_unknown_intent,
            }

            handler = handlers.get(intent, self._handle_unknown_intent)
            return await handler(msg=msg, session=session, is_first_visit=is_first_visit)

        except Exception as exc:
            logger.error(
                f"[{msg.request_id}] Response generation failed: {exc}",
                exc_info=True,
                extra={"event": "RESPONSE_GEN_ERROR"}
            )
            return "I encountered a temporary issue. Please try again in a moment. 🙏"

    async def _handle_greeting(self, msg: IncomingMessage, session: UserSession, is_first_visit: bool) -> str:
        if is_first_visit:
            return (
                "👋 Welcome to *CypherCore*! I'm your secure AI assistant.\n\n"
                "I can help you with:\n"
                "• 🔍 Information & instant answers\n"
                "• 🤝 Business support & onboarding\n"
                "• 🔐 Account & security management\n"
                "• 📞 Escalation to a live agent\n\n"
                "Simply tell me what you need — I'm always here. What can I help you with today?"
            )
        return "Welcome back! 👋 Good to hear from you again. What can I help you with?"

    async def _handle_farewell(self, msg: IncomingMessage, session: UserSession, is_first_visit: bool) -> str:
        session.state = ConversationState.NEW  # Reset for next conversation
        return (
            "Goodbye! 👋 It was great assisting you.\n\n"
            "Feel free to message anytime — CypherCore is always here for you. Take care! 😊"
        )

    async def _handle_help(self, msg: IncomingMessage, session: UserSession, is_first_visit: bool) -> str:
        return (
            "I'm here to help! 🤝\n\n"
            "*What I can do for you:*\n"
            "• Answer questions instantly\n"
            "• Walk you through any process step by step\n"
            "• Connect you with the right team if needed\n\n"
            "Please describe your issue in detail and I'll take care of it.\n"
            "_Typical response time: under 30 seconds._ ⚡"
        )

    async def _handle_affirmative(self, msg: IncomingMessage, session: UserSession, is_first_visit: bool) -> str:
        # Context-aware: check if bot asked a question last turn
        pending_question = session.context.get("pending_question")
        if pending_question:
            del session.context["pending_question"]
            return f"Great! Let me proceed with that for you. ✅\n\n_(Confirmed: {pending_question})_"
        return "Got it! ✅ Is there anything else I can help you with?"

    async def _handle_negative(self, msg: IncomingMessage, session: UserSession, is_first_visit: bool) -> str:
        pending_question = session.context.get("pending_question")
        if pending_question:
            del session.context["pending_question"]
            return "Understood, I won't proceed. ✋ Let me know if you'd like to do something else."
        return "No problem! 😊 Let me know if there's anything else I can help with."

    async def _handle_unknown_intent(self, msg: IncomingMessage, session: UserSession, is_first_visit: bool) -> str:
        """
        Fallback handler — production LLM integration point.

        Replace the body of this method with an LLM API call.
        The interface (args, return type) must remain unchanged.
        """
        preview = msg.text_body[:Cfg.PREVIEW_LENGTH]
        return (
            f"Thanks for your message! 💬\n\n"
            f"I received: _\"{preview}{'...' if len(msg.text_body) > Cfg.PREVIEW_LENGTH else ''}\"_\n\n"
            "I'm working on an accurate response for you. "
            "If this is urgent, type *help* to reach our support team immediately. 🚀"
        )

    # ── Meta API Communication ────────────────────────────────────────────────

    async def _send_typing_indicator(self, phone: str, request_id: str) -> None:
        """
        Send a typing indicator to the user (professional UX — shows bot is working).

        This is fire-and-forget. Failures are logged but never propagate.
        The indicator is followed by a short delay that mimics realistic typing time.
        """
        if not self.http_client or self.circuit_breaker.is_open:
            return

        url = f"{Cfg.API_BASE}/{self.api_version}/{self.phone_id}/messages"
        payload = {
            "messaging_product": "whatsapp",
            "to":    phone,
            "type":  "reaction",
            "status": "read",
        }
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type":  "application/json",
        }

        try:
            await self.http_client.post(url, json=payload, headers=headers, timeout=5.0)
            await asyncio.sleep(Cfg.TYPING_INDICATOR_MS / 1000)  # Simulate typing delay
        except Exception:
            pass  # Typing indicator is best-effort only — never fail on this

    async def send_message(self, outgoing: OutgoingMessage) -> SendResult:
        """
        Send a WhatsApp message with circuit breaker, retry, and exponential backoff.

        Failure strategy:
            Transient (429, 5xx, timeout) → retry up to max_retries with backoff
            Permanent (4xx except 429)    → fail immediately, log, return error
            Circuit open                  → fail immediately without attempting

        Args:
            outgoing: Typed outgoing message (never raw dict)

        Returns:
            SendResult (always — never raises)
        """
        if not self.http_client:
            logger.error(
                f"[{outgoing.request_id}] HTTP client not initialized",
                extra={"event": "NO_HTTP_CLIENT"}
            )
            return SendResult(success=False, status="client_not_initialized")

        if self.circuit_breaker.is_open:
            logger.error(
                f"[{outgoing.request_id}] Circuit breaker OPEN — aborting send",
                extra={"event": "CIRCUIT_OPEN"}
            )
            return SendResult(success=False, status="circuit_open")

        url = f"{Cfg.API_BASE}/{self.api_version}/{self.phone_id}/messages"
        payload = {
            "messaging_product": "whatsapp",
            "to":   outgoing.to_phone,
            "type": "text",
            "text": {"body": outgoing.message_text},
        }
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type":  "application/json",
        }

        retry_delay = Cfg.RETRY_BASE_DELAY

        while outgoing.retry_count < outgoing.max_retries:
            try:
                logger.debug(
                    f"[{outgoing.request_id}] Send attempt "
                    f"{outgoing.retry_count + 1}/{outgoing.max_retries} to {outgoing.to_phone}",
                    extra={"event": "SEND_ATTEMPT", "attempt": outgoing.retry_count + 1}
                )

                response = await self.http_client.post(
                    url, json=payload, headers=headers, timeout=Cfg.API_TIMEOUT
                )

                if response.status_code in (200, 201):
                    self.circuit_breaker.record_success()
                    logger.info(
                        f"[{outgoing.request_id}] Message sent to {outgoing.to_phone}",
                        extra={"event": "MESSAGE_SENT", "status_code": response.status_code}
                    )
                    return SendResult(
                        success=True,
                        status="sent",
                        status_code=response.status_code,
                        meta_data=response.json(),
                    )

                # Transient errors → retry
                if response.status_code in (429, 500, 502, 503, 504):
                    outgoing.retry_count += 1
                    self.circuit_breaker.record_failure()
                    if outgoing.retry_count < outgoing.max_retries:
                        logger.warning(
                            f"[{outgoing.request_id}] Transient {response.status_code} — "
                            f"retry in {retry_delay}s",
                            extra={"event": "TRANSIENT_ERROR", "status_code": response.status_code}
                        )
                        await asyncio.sleep(retry_delay)
                        retry_delay *= 2  # Exponential backoff
                        continue
                    logger.error(
                        f"[{outgoing.request_id}] Max retries exhausted for {outgoing.to_phone}",
                        extra={"event": "MAX_RETRIES_EXHAUSTED"}
                    )
                    return SendResult(success=False, status="failed_max_retries",
                                      status_code=response.status_code)

                # Permanent error → do not retry
                self.circuit_breaker.record_failure()
                logger.error(
                    f"[{outgoing.request_id}] Permanent API error {response.status_code}: "
                    f"{response.text[:200]}",
                    extra={"event": "PERMANENT_API_ERROR", "status_code": response.status_code}
                )
                return SendResult(success=False, status="api_error",
                                  status_code=response.status_code)

            except asyncio.TimeoutError:
                outgoing.retry_count += 1
                self.circuit_breaker.record_failure()
                if outgoing.retry_count < outgoing.max_retries:
                    logger.warning(
                        f"[{outgoing.request_id}] Timeout — retry in {retry_delay}s",
                        extra={"event": "TIMEOUT", "retry_count": outgoing.retry_count}
                    )
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2
                    continue
                logger.error(
                    f"[{outgoing.request_id}] Timeout — max retries exhausted",
                    extra={"event": "TIMEOUT_MAX_RETRIES"}
                )
                return SendResult(success=False, status="timeout_max_retries")

            except httpx.RequestError as exc:
                self.circuit_breaker.record_failure()
                logger.error(
                    f"[{outgoing.request_id}] Network error: {exc}",
                    exc_info=True,
                    extra={"event": "NETWORK_ERROR"}
                )
                return SendResult(success=False, status="network_error")

            except Exception as exc:
                self.circuit_breaker.record_failure()
                logger.error(
                    f"[{outgoing.request_id}] Unexpected send error: {exc}",
                    exc_info=True,
                    extra={"event": "UNEXPECTED_SEND_ERROR"}
                )
                return SendResult(success=False, status="unexpected_error")

        return SendResult(success=False, status="send_failed_all_retries")

    # ── Maintenance ───────────────────────────────────────────────────────────

    async def sweep(self) -> None:
        """
        Periodic maintenance sweep. Call from a background task (e.g. every 5 minutes).

        Operations:
            - Evict expired sessions (prevents unbounded memory growth)
        """
        swept = self.sessions.sweep_expired()
        logger.debug(f"Sweep complete — {swept} sessions evicted", extra={"event": "SWEEP_DONE"})

    async def close(self) -> None:
        """
        Gracefully shutdown the processor. Safe to call multiple times.
        Call this in the application shutdown hook.
        """
        if self._closed:
            return
        self._closed = True

        if self.http_client:
            try:
                await self.http_client.aclose()
                logger.info("HTTP client closed cleanly", extra={"event": "HTTP_CLOSED"})
            except Exception as exc:
                logger.error(f"Error closing HTTP client: {exc}", exc_info=True)
