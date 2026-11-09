
import logging
import os
import smtplib
import ssl
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

from dotenv import load_dotenv

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
)

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.models.pending_registration import PendingRegistration

from app.schemas.auth import (
    RegisterRequest,
    LoginRequest,
    UserResponse,
    TokenResponse,
    TwoFactorVerifyRequest,
    TotpSetupResponse,
    TwoFactorSetupVerifyRequest,
    TwoFactorStatusResponse,
    RegistrationStartResponse,
    RegistrationEmailVerifyRequest,
    RegistrationEmailVerifyResponse,
    RegistrationTwoFactorMethodRequest,
    RegistrationTotpSetupResponse,
    RegistrationTwoFactorVerifyRequest,
    RegistrationCompleteResponse,
    RegistrationResendOtpResponse,
)

from app.security.auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    create_pending_2fa_token,
    decode_pending_2fa_payload,
    create_registration_token,
    decode_registration_token,
    create_enrollment_token,
    decode_enrollment_token,
    generate_email_otp,
    hash_otp,
    verify_otp,
    generate_totp_secret,
    get_totp_provisioning_uri,
    get_totp_matching_step,
    encrypt_totp_secret,
    decrypt_totp_secret,
)


load_dotenv()

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/auth",
    tags=["Authentication"],
)

bearer_scheme = HTTPBearer(auto_error=False)
pending_bearer_scheme = HTTPBearer(auto_error=False)
registration_bearer_scheme = HTTPBearer(auto_error=False)
enrollment_bearer_scheme = HTTPBearer(auto_error=False)


# =========================================================
# CONFIGURATION
# =========================================================

OTP_EXPIRE_MINUTES = int(
    os.getenv("EMAIL_OTP_EXPIRE_MINUTES", "5")
)

OTP_RESEND_SECONDS = int(
    os.getenv("EMAIL_OTP_RESEND_SECONDS", "60")
)

OTP_MAX_ATTEMPTS = int(
    os.getenv("EMAIL_OTP_MAX_ATTEMPTS", "5")
)

PENDING_REGISTRATION_EXPIRE_MINUTES = int(
    os.getenv("PENDING_REGISTRATION_EXPIRE_MINUTES", "30")
)

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL")
SMTP_TIMEOUT_SECONDS = int(os.getenv("SMTP_TIMEOUT_SECONDS", "20"))
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").strip().lower() == "true"
SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "false").strip().lower() == "true"


# =========================================================
# COMMON HELPERS
# =========================================================

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


def ensure_not_expired(expires_at: datetime) -> None:
    if utc_now() >= normalize_datetime(expires_at):
        raise HTTPException(
            status_code=401,
            detail="This registration has expired. Please register again.",
        )


def commit_changes(db: Session, message: str) -> None:
    try:
        db.commit()

    except SQLAlchemyError:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=message,
        )


# =========================================================
# EMAIL DELIVERY
# =========================================================

def send_email_otp(
    recipient: str,
    otp: str,
    purpose: str = "verification",
) -> None:
    """Send an OTP using Gmail SMTP (App Password required for Gmail)."""
    required_settings = {
        "SMTP_HOST": SMTP_HOST,
        "SMTP_USERNAME": SMTP_USERNAME,
        "SMTP_PASSWORD": SMTP_PASSWORD,
        "SMTP_FROM_EMAIL": SMTP_FROM_EMAIL,
    }
    missing_settings = [name for name, value in required_settings.items() if not value]

    if missing_settings:
        logger.error("Email configuration is incomplete; missing: %s", ", ".join(missing_settings))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Email service is not configured. Check the backend SMTP environment variables.",
        )

    if SMTP_USE_SSL and SMTP_USE_TLS:
        logger.error("Invalid SMTP configuration: SMTP_USE_SSL and SMTP_USE_TLS cannot both be true.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Email service configuration is invalid.",
        )

    if purpose == "registration":
        subject = "IDPS Shield - Email Verification"
        heading = "Verify your email address"
    elif purpose == "two_factor":
        subject = "IDPS Shield - Two-Factor Authentication"
        heading = "Your login verification code"
    else:
        subject = "IDPS Shield - Verification Code"
        heading = "Your verification code"

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = SMTP_FROM_EMAIL
    message["To"] = recipient
    message.set_content(
        f"""Hello,

{heading}

Your IDPS Shield verification code is:

{otp}

This code expires in {OTP_EXPIRE_MINUTES} minutes.

Do not share this code with anyone.

If you did not request this code, you can ignore this email.

IDPS Shield Security Team
"""
    )

    try:
        tls_context = ssl.create_default_context()

        if SMTP_USE_SSL:
            # Use only when the SMTP provider supports implicit TLS (commonly port 465).
            with smtplib.SMTP_SSL(
                SMTP_HOST,
                SMTP_PORT,
                timeout=SMTP_TIMEOUT_SECONDS,
                context=tls_context,
            ) as server:
                server.ehlo()
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(message)
        else:
            # Gmail's usual submission setting is port 587 with STARTTLS.
            with smtplib.SMTP(
                SMTP_HOST,
                SMTP_PORT,
                timeout=SMTP_TIMEOUT_SECONDS,
            ) as server:
                server.ehlo()
                if SMTP_USE_TLS:
                    server.starttls(context=tls_context)
                    server.ehlo()
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(message)

    except (smtplib.SMTPException, OSError, TimeoutError, ssl.SSLError):
        # Keep the detailed exception in Render logs, but never expose credentials
        # or provider responses to the frontend.
        logger.exception(
            "Gmail SMTP delivery failed (host=%s, port=%s, ssl=%s, starttls=%s).",
            SMTP_HOST,
            SMTP_PORT,
            SMTP_USE_SSL,
            SMTP_USE_TLS,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to send verification email. Check the backend email service and Render logs.",
        )
    except Exception:
        logger.exception("Unexpected error while sending an IDPS verification email.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to send verification email. Check the backend logs.",
        )


# =========================================================
# OTP HELPERS
# =========================================================

def check_resend_cooldown(last_sent_at: datetime | None) -> None:
    if not last_sent_at:
        return

    elapsed = (
        utc_now() - normalize_datetime(last_sent_at)
    ).total_seconds()

    if elapsed < OTP_RESEND_SECONDS:
        remaining = int(
            OTP_RESEND_SECONDS - elapsed
        ) + 1

        raise HTTPException(
            status_code=429,
            detail=f"Please wait {remaining} seconds before requesting another OTP.",
        )


def validate_otp_fields(
    otp_hash: str | None,
    expires_at: datetime | None,
    attempts: int,
    submitted_code: str,
) -> bool:

    if not otp_hash or not expires_at:
        raise HTTPException(
            status_code=400,
            detail="No active verification code. Request a new code.",
        )

    if utc_now() >= normalize_datetime(expires_at):
        return False

    if attempts >= OTP_MAX_ATTEMPTS:
        return False

    if not verify_otp(submitted_code, otp_hash):
        return False

    return True


def clear_otp_fields(record) -> None:
    record.email_otp_hash = None
    record.email_otp_expires_at = None
    record.email_otp_attempts = 0
    record.email_otp_last_sent_at = None


def send_pending_registration_otp(
    pending: PendingRegistration,
    db: Session,
    purpose: str = "registration",
) -> None:

    check_resend_cooldown(
        pending.email_otp_last_sent_at
    )

    otp = generate_email_otp()

    pending.email_otp_hash = hash_otp(otp)
    pending.email_otp_expires_at = (
        utc_now() + timedelta(minutes=OTP_EXPIRE_MINUTES)
    )
    pending.email_otp_attempts = 0
    pending.email_otp_last_sent_at = utc_now()

    commit_changes(
        db,
        "Unable to save verification code.",
    )

    send_email_otp(
        pending.email,
        otp,
        purpose,
    )


def create_and_send_user_otp(
    user: User,
    db: Session,
) -> None:

    check_resend_cooldown(
        user.email_otp_last_sent_at
    )

    otp = generate_email_otp()

    user.email_otp_hash = hash_otp(otp)
    user.email_otp_expires_at = (
        utc_now() + timedelta(minutes=OTP_EXPIRE_MINUTES)
    )
    user.email_otp_attempts = 0
    user.email_otp_last_sent_at = utc_now()

    commit_changes(
        db,
        "Unable to save verification code.",
    )

    send_email_otp(
        user.email,
        otp,
        "two_factor",
    )


def validate_user_email_otp(
    user: User,
    submitted_code: str,
) -> bool:

    valid = validate_otp_fields(
        user.email_otp_hash,
        user.email_otp_expires_at,
        user.email_otp_attempts or 0,
        submitted_code,
    )

    if not valid:
        user.email_otp_attempts = (
            user.email_otp_attempts or 0
        ) + 1

        if user.email_otp_attempts >= OTP_MAX_ATTEMPTS:
            clear_otp_fields(user)

    return valid


# =========================================================
# AUTHENTICATED USER DEPENDENCY
# =========================================================

def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme
    ),
    db: Session = Depends(get_db),
) -> User:

    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = decode_access_token(
        credentials.credentials
    )

    if user_id is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token.",
        )

    user = db.get(User, user_id)

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="User account not found.",
        )

    # Defense in depth: an account without completed
    # email verification and 2FA cannot use protected APIs.
    if (
        not user.email_verified
        or not user.two_factor_enabled
        or user.two_factor_method not in ("totp", "email")
    ):
        raise HTTPException(
            status_code=403,
            detail="Email verification and two-factor authentication are required.",
        )

    return user


# =========================================================
# PENDING LOGIN 2FA DEPENDENCY
# =========================================================

def get_pending_2fa_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        pending_bearer_scheme
    ),
    db: Session = Depends(get_db),
) -> tuple[User, dict]:

    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="2FA challenge token required.",
        )

    payload = decode_pending_2fa_payload(
        credentials.credentials
    )

    if payload is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired 2FA challenge.",
        )

    try:
        user_id = int(payload["sub"])

    except (ValueError, TypeError, KeyError):
        raise HTTPException(
            status_code=401,
            detail="Invalid 2FA challenge.",
        )

    user = db.get(User, user_id)

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="User account not found.",
        )

    return user, payload


# =========================================================
# REGISTRATION TOKEN DEPENDENCY
# =========================================================

def get_pending_registration(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        registration_bearer_scheme
    ),
    db: Session = Depends(get_db),
) -> PendingRegistration:

    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="Registration token required.",
        )

    pending_id = decode_registration_token(
        credentials.credentials
    )

    if pending_id is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired registration token.",
        )

    pending = db.get(
        PendingRegistration,
        pending_id,
    )

    if pending is None:
        raise HTTPException(
            status_code=404,
            detail="Pending registration not found.",
        )

    ensure_not_expired(pending.expires_at)

    return pending


# =========================================================
# 2FA ENROLLMENT TOKEN DEPENDENCY
# =========================================================

def get_pending_enrollment(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        enrollment_bearer_scheme
    ),
    db: Session = Depends(get_db),
) -> PendingRegistration:

    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="Enrollment token required.",
        )

    pending_id = decode_enrollment_token(
        credentials.credentials
    )

    if pending_id is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired enrollment token.",
        )

    pending = db.get(
        PendingRegistration,
        pending_id,
    )

    if pending is None:
        raise HTTPException(
            status_code=404,
            detail="Pending registration not found.",
        )

    ensure_not_expired(pending.expires_at)

    if not pending.email_verified:
        raise HTTPException(
            status_code=403,
            detail="Verify your email before configuring 2FA.",
        )

    return pending


# =========================================================
# REGISTRATION - START
# =========================================================

@router.post(
    "/register",
    response_model=RegistrationStartResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    data: RegisterRequest,
    db: Session = Depends(get_db),
):

    email = str(data.email).strip().lower()
    name = data.name.strip()

    existing_user = db.scalar(
        select(User).where(User.email == email)
    )

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists.",
        )

    existing_pending = db.scalar(
        select(PendingRegistration).where(
            PendingRegistration.email == email
        )
    )

    if existing_pending:
        if (
            utc_now()
            < normalize_datetime(existing_pending.expires_at)
        ):
            raise HTTPException(
                status_code=409,
                detail="A registration is already pending for this email. Complete it or wait for it to expire.",
            )

        db.delete(existing_pending)
        db.commit()

    pending = PendingRegistration(
        name=name,
        email=email,
        password_hash=hash_password(data.password),
        date_of_birth=data.date_of_birth,
        email_verified=False,
        email_otp_attempts=0,
        expires_at=(
            utc_now()
            + timedelta(
                minutes=PENDING_REGISTRATION_EXPIRE_MINUTES
            )
        ),
    )

    try:
        db.add(pending)
        db.commit()
        db.refresh(pending)

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=409,
            detail="A registration already exists for this email.",
        )

    except SQLAlchemyError:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Unable to start registration.",
        )

    registration_token = create_registration_token(
        pending.id
    )

    try:
        send_pending_registration_otp(
            pending,
            db,
            purpose="registration",
        )

    except HTTPException:
        # The registration token is not returned when this endpoint fails.
        # Remove the newly-created pending row so the user can retry registration
        # instead of being permanently blocked by a 409 Conflict.
        try:
            db.delete(pending)
            db.commit()
        except SQLAlchemyError:
            db.rollback()
            logger.exception("Could not clean up pending registration after email delivery failed.")
        raise

    return RegistrationStartResponse(
        registration_token=registration_token,
        expires_in=PENDING_REGISTRATION_EXPIRE_MINUTES * 60,
        message="Registration started. Check your email for the verification code.",
    )


# =========================================================
# REGISTRATION - RESEND EMAIL OTP
# =========================================================

@router.post(
    "/register/resend-email",
    response_model=RegistrationResendOtpResponse,
)
def resend_registration_email(
    pending: PendingRegistration = Depends(
        get_pending_registration
    ),
    db: Session = Depends(get_db),
):

    if pending.email_verified:
        raise HTTPException(
            status_code=409,
            detail="Email has already been verified.",
        )

    send_pending_registration_otp(
        pending,
        db,
        purpose="registration",
    )

    return RegistrationResendOtpResponse(
        message="A new email verification code has been sent.",
        expires_in=OTP_EXPIRE_MINUTES * 60,
    )


# =========================================================
# REGISTRATION - VERIFY EMAIL
# =========================================================

@router.post(
    "/register/verify-email",
    response_model=RegistrationEmailVerifyResponse,
)
def verify_registration_email(
    data: RegistrationEmailVerifyRequest,
    pending: PendingRegistration = Depends(
        get_pending_registration
    ),
    db: Session = Depends(get_db),
):

    if pending.email_verified:
        raise HTTPException(
            status_code=409,
            detail="Email has already been verified.",
        )

    valid = validate_otp_fields(
        pending.email_otp_hash,
        pending.email_otp_expires_at,
        pending.email_otp_attempts or 0,
        data.code,
    )

    if not valid:
        pending.email_otp_attempts = (
            pending.email_otp_attempts or 0
        ) + 1

        if pending.email_otp_attempts >= OTP_MAX_ATTEMPTS:
            clear_otp_fields(pending)

        commit_changes(
            db,
            "Unable to update verification attempts.",
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid or expired email verification code.",
        )

    clear_otp_fields(pending)
    pending.email_verified = True

    commit_changes(
        db,
        "Unable to verify email address.",
    )

    enrollment_token = create_enrollment_token(
        pending.id
    )

    return RegistrationEmailVerifyResponse(
        email_verified=True,
        requires_two_factor_setup=True,
        enrollment_token=enrollment_token,
        available_methods=["totp", "email"],
        message="Email verified. Choose your two-factor authentication method.",
    )


# =========================================================
# REGISTRATION - SELECT 2FA METHOD
# =========================================================

@router.post("/register/2fa/method")
def select_registration_2fa_method(
    data: RegistrationTwoFactorMethodRequest,
    pending: PendingRegistration = Depends(
        get_pending_enrollment
    ),
    db: Session = Depends(get_db),
):

    pending.two_factor_method = data.method

    # Reset any previous unconfirmed authenticator setup.
    pending.totp_secret = None
    pending.totp_last_used_step = None

    clear_otp_fields(pending)

    commit_changes(
        db,
        "Unable to save two-factor authentication method.",
    )

    return {
        "message": (
            "Google Authenticator selected."
            if data.method == "totp"
            else "Email OTP selected."
        ),
        "two_factor_method": data.method,
    }


# =========================================================
# REGISTRATION - TOTP SETUP
# =========================================================

@router.post(
    "/register/2fa/totp/setup",
    response_model=RegistrationTotpSetupResponse,
)
def setup_registration_totp(
    pending: PendingRegistration = Depends(
        get_pending_enrollment
    ),
    db: Session = Depends(get_db),
):

    if pending.two_factor_method != "totp":
        raise HTTPException(
            status_code=400,
            detail="Select Google Authenticator first.",
        )

    secret = generate_totp_secret()

    pending.totp_secret = encrypt_totp_secret(
        secret
    )

    pending.totp_last_used_step = None

    commit_changes(
        db,
        "Unable to save authenticator setup.",
    )

    provisioning_uri = get_totp_provisioning_uri(
        secret,
        pending.email,
        issuer="IDPS Shield",
    )

    return RegistrationTotpSetupResponse(
        secret=secret,
        provisioning_uri=provisioning_uri,
        message="Scan the QR code with Google Authenticator and verify the six-digit code to finish registration.",
    )


# =========================================================
# REGISTRATION - EMAIL OTP SETUP
# =========================================================

@router.post(
    "/register/2fa/email/setup",
    response_model=RegistrationResendOtpResponse,
)
def setup_registration_email_2fa(
    pending: PendingRegistration = Depends(
        get_pending_enrollment
    ),
    db: Session = Depends(get_db),
):

    if pending.two_factor_method != "email":
        raise HTTPException(
            status_code=400,
            detail="Select Email OTP first.",
        )

    send_pending_registration_otp(
        pending,
        db,
        purpose="two_factor",
    )

    return RegistrationResendOtpResponse(
        message="Your two-factor authentication code has been sent.",
        expires_in=OTP_EXPIRE_MINUTES * 60,
    )


# =========================================================
# REGISTRATION - COMPLETE ACCOUNT
# =========================================================

@router.post(
    "/register/complete",
    response_model=RegistrationCompleteResponse,
    status_code=status.HTTP_201_CREATED,
)
def complete_registration(
    data: RegistrationTwoFactorVerifyRequest,
    pending: PendingRegistration = Depends(
        get_pending_enrollment
    ),
    db: Session = Depends(get_db),
):

    if pending.two_factor_method not in ("totp", "email"):
        raise HTTPException(
            status_code=400,
            detail="Select a two-factor authentication method first.",
        )

    matching_step = None

    # ---------------------------------------------
    # Verify Google Authenticator
    # ---------------------------------------------

    if pending.two_factor_method == "totp":

        if not pending.totp_secret:
            raise HTTPException(
                status_code=400,
                detail="Complete authenticator setup first.",
            )

        try:
            secret = decrypt_totp_secret(
                pending.totp_secret
            )

        except ValueError:
            raise HTTPException(
                status_code=500,
                detail="Unable to read authenticator configuration.",
            )

        matching_step = get_totp_matching_step(
            secret,
            data.code,
            valid_window=1,
        )

        if matching_step is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid authenticator code.",
            )

        if (
            pending.totp_last_used_step is not None
            and matching_step <= pending.totp_last_used_step
        ):
            raise HTTPException(
                status_code=401,
                detail="This authenticator code has already been used.",
            )

    # ---------------------------------------------
    # Verify Email OTP
    # ---------------------------------------------

    elif pending.two_factor_method == "email":

        valid = validate_otp_fields(
            pending.email_otp_hash,
            pending.email_otp_expires_at,
            pending.email_otp_attempts or 0,
            data.code,
        )

        if not valid:
            pending.email_otp_attempts = (
                pending.email_otp_attempts or 0
            ) + 1

            if pending.email_otp_attempts >= OTP_MAX_ATTEMPTS:
                clear_otp_fields(pending)

            commit_changes(
                db,
                "Unable to update verification attempts.",
            )

            raise HTTPException(
                status_code=401,
                detail="Invalid or expired email verification code.",
            )

    # ---------------------------------------------
    # Prevent duplicate account creation
    # ---------------------------------------------

    existing_user = db.scalar(
        select(User).where(
            User.email == pending.email
        )
    )

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists.",
        )

    # ---------------------------------------------
    # Create final active user
    # ---------------------------------------------

    user = User(
        name=pending.name,
        email=pending.email,
        password_hash=pending.password_hash,
        role="USER",
        date_of_birth=pending.date_of_birth,
        auth_provider="email",
        email_verified=True,
        two_factor_enabled=True,
        two_factor_method=pending.two_factor_method,
        totp_enabled=(
            pending.two_factor_method == "totp"
        ),
        email_otp_enabled=(
            pending.two_factor_method == "email"
        ),
        totp_secret=(
            pending.totp_secret
            if pending.two_factor_method == "totp"
            else None
        ),
        totp_last_used_step=matching_step,
    )

    try:
        db.add(user)

        # Deleting the pending row invalidates all enrollment
        # tokens for this registration.
        db.delete(pending)

        db.commit()
        db.refresh(user)

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists.",
        )

    except SQLAlchemyError:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Unable to complete registration.",
        )

    access_token = create_access_token(
        user.id
    )

    return RegistrationCompleteResponse(
        registration_complete=True,
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
    )


# =========================================================
# LOGIN
# =========================================================

@router.post("/login")
def login(
    data: LoginRequest,
    db: Session = Depends(get_db),
):

    email = str(data.email).strip().lower()

    user = db.scalar(
        select(User).where(
            User.email == email
        )
    )

    if (
        user is None
        or not user.password_hash
        or not verify_password(
            data.password,
            user.password_hash,
        )
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password.",
        )

    if not user.email_verified:
        raise HTTPException(
            status_code=403,
            detail="Email verification is required. Contact support to recover or complete your account verification.",
        )

    # Never issue an access token to an account without 2FA.
    if (
        not user.two_factor_enabled
        or user.two_factor_method not in ("totp", "email")
    ):
        raise HTTPException(
            status_code=403,
            detail="Two-factor authentication enrollment is required before login. Contact support to complete account enrollment.",
        )

    method = user.two_factor_method

    if method == "totp" and (
        not user.totp_enabled or not user.totp_secret
    ):
        raise HTTPException(
            status_code=403,
            detail="Authenticator configuration is incomplete. Contact support.",
        )

    if method == "email" and not user.email_otp_enabled:
        raise HTTPException(
            status_code=403,
            detail="Email OTP configuration is incomplete. Contact support.",
        )

    challenge_token = create_pending_2fa_token(
        user.id,
        method=method,
    )

    if method == "email":
        create_and_send_user_otp(
            user,
            db,
        )

    return {
        "requires_two_factor": True,
        "challenge_token": challenge_token,
        "available_methods": [method],
        "expires_in": 300,
        "message": "Complete two-factor verification to sign in.",
    }


# =========================================================
# LOGIN - VERIFY 2FA
# =========================================================

@router.post("/verify-2fa")
def verify_login_2fa(
    data: TwoFactorVerifyRequest,
    challenge: tuple[User, dict] = Depends(
        get_pending_2fa_user
    ),
    db: Session = Depends(get_db),
):

    user, payload = challenge
    method = payload.get("method")

    if method != user.two_factor_method:
        raise HTTPException(
            status_code=401,
            detail="Authentication method does not match.",
        )

    if (
        not user.two_factor_enabled
        or not user.email_verified
    ):
        raise HTTPException(
            status_code=403,
            detail="Email verification and 2FA are required.",
        )

    if method == "totp":

        if not user.totp_enabled or not user.totp_secret:
            raise HTTPException(
                status_code=400,
                detail="Authenticator is not configured.",
            )

        try:
            secret = decrypt_totp_secret(
                user.totp_secret
            )

        except ValueError:
            raise HTTPException(
                status_code=500,
                detail="Unable to verify authenticator configuration.",
            )

        matching_step = get_totp_matching_step(
            secret,
            data.code,
            valid_window=1,
        )

        if matching_step is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid authenticator code.",
            )

        if (
            user.totp_last_used_step is not None
            and matching_step <= user.totp_last_used_step
        ):
            raise HTTPException(
                status_code=401,
                detail="This authenticator code has already been used.",
            )

        user.totp_last_used_step = matching_step

    elif method == "email":

        if not user.email_otp_enabled:
            raise HTTPException(
                status_code=400,
                detail="Email OTP is not enabled.",
            )

        if not validate_user_email_otp(
            user,
            data.code,
        ):
            commit_changes(
                db,
                "Unable to update OTP verification attempts.",
            )

            raise HTTPException(
                status_code=401,
                detail="Invalid or expired email verification code.",
            )

        clear_otp_fields(user)

    else:
        raise HTTPException(
            status_code=400,
            detail="Unsupported authentication method.",
        )

    commit_changes(
        db,
        "Unable to complete authentication.",
    )

    db.refresh(user)

    token = create_access_token(
        user.id
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
    )


# =========================================================
# LOGIN - RESEND EMAIL OTP
# =========================================================

@router.post("/2fa/resend-email")
def resend_login_email_otp(
    challenge: tuple[User, dict] = Depends(
        get_pending_2fa_user
    ),
    db: Session = Depends(get_db),
):

    user, payload = challenge

    if (
        payload.get("method") != "email"
        or user.two_factor_method != "email"
        or not user.two_factor_enabled
        or not user.email_otp_enabled
    ):
        raise HTTPException(
            status_code=400,
            detail="Email OTP is not the selected authentication method.",
        )

    create_and_send_user_otp(
        user,
        db,
    )

    return {
        "message": "A new verification code has been sent.",
        "expires_in": OTP_EXPIRE_MINUTES * 60,
    }


# =========================================================
# EXISTING USER - TOTP SETUP
# =========================================================

@router.post(
    "/2fa/totp/setup",
    response_model=TotpSetupResponse,
)
def setup_totp(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):

    if current_user.totp_enabled:
        raise HTTPException(
            status_code=409,
            detail="Authenticator is already enabled.",
        )

    secret = generate_totp_secret()

    current_user.totp_secret = encrypt_totp_secret(
        secret
    )

    current_user.totp_last_used_step = None

    commit_changes(
        db,
        "Unable to save authenticator setup.",
    )

    return TotpSetupResponse(
        secret=secret,
        provisioning_uri=get_totp_provisioning_uri(
            secret,
            current_user.email,
            issuer="IDPS Shield",
        ),
        message="Scan the QR code with your authenticator app, then verify the six-digit code.",
    )


# =========================================================
# EXISTING USER - CONFIRM TOTP
# =========================================================

@router.post("/2fa/totp/confirm")
def confirm_totp_setup(
    data: TwoFactorSetupVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):

    if not current_user.totp_secret:
        raise HTTPException(
            status_code=400,
            detail="Start authenticator setup first.",
        )

    if current_user.totp_enabled:
        raise HTTPException(
            status_code=409,
            detail="Authenticator is already enabled.",
        )

    try:
        secret = decrypt_totp_secret(
            current_user.totp_secret
        )

    except ValueError:
        raise HTTPException(
            status_code=500,
            detail="Unable to read authenticator setup.",
        )

    matching_step = get_totp_matching_step(
        secret,
        data.code,
        valid_window=1,
    )

    if matching_step is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid authenticator code.",
        )

    current_user.totp_enabled = True
    current_user.email_otp_enabled = False
    current_user.two_factor_enabled = True
    current_user.two_factor_method = "totp"
    current_user.totp_last_used_step = matching_step

    commit_changes(
        db,
        "Unable to enable authenticator.",
    )

    db.refresh(current_user)

    return {
        "message": "Google Authenticator has been enabled successfully.",
        "two_factor_enabled": True,
        "two_factor_method": "totp",
    }


# =========================================================
# EXISTING USER - EMAIL OTP SETUP
# =========================================================

@router.post("/2fa/email/setup")
def setup_email_otp(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):

    create_and_send_user_otp(
        current_user,
        db,
    )

    return {
        "message": "A verification code has been sent to your registered email.",
        "expires_in": OTP_EXPIRE_MINUTES * 60,
    }


# =========================================================
# EXISTING USER - CONFIRM EMAIL OTP
# =========================================================

@router.post("/2fa/email/confirm")
def confirm_email_otp_setup(
    data: TwoFactorSetupVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):

    if not validate_user_email_otp(
        current_user,
        data.code,
    ):
        commit_changes(
            db,
            "Unable to update verification attempts.",
        )

        raise HTTPException(
            status_code=400,
            detail="Invalid or expired verification code.",
        )

    clear_otp_fields(current_user)

    current_user.email_verified = True
    current_user.email_otp_enabled = True
    current_user.totp_enabled = False
    current_user.two_factor_enabled = True
    current_user.two_factor_method = "email"

    current_user.totp_secret = None
    current_user.totp_last_used_step = None

    commit_changes(
        db,
        "Unable to enable email verification.",
    )

    db.refresh(current_user)

    return {
        "message": "Email OTP authentication has been enabled successfully.",
        "two_factor_enabled": True,
        "two_factor_method": "email",
    }


# =========================================================
# TWO-FACTOR STATUS
# =========================================================

@router.get(
    "/2fa/status",
    response_model=TwoFactorStatusResponse,
)
def get_two_factor_status(
    current_user: User = Depends(get_current_user),
):

    return TwoFactorStatusResponse(
        two_factor_enabled=current_user.two_factor_enabled,
        two_factor_method=current_user.two_factor_method,
        totp_enabled=current_user.totp_enabled,
        email_otp_enabled=current_user.email_otp_enabled,
    )


# =========================================================
# CURRENT USER
# =========================================================

@router.get(
    "/me",
    response_model=UserResponse,
)
def get_me(
    current_user: User = Depends(get_current_user),
):

    return UserResponse.model_validate(
        current_user
    )
