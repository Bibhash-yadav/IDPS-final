
import os
import secrets
import hmac
import hashlib

from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from jose import JWTError, jwt
from passlib.context import CryptContext
from cryptography.fernet import Fernet, InvalidToken

import pyotp


load_dotenv()


# =========================================================
# CONFIGURATION
# =========================================================

JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

TOKEN_EXPIRE_MINUTES = int(
    os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
)

PENDING_2FA_EXPIRE_MINUTES = int(
    os.getenv("PENDING_2FA_EXPIRE_MINUTES", "5")
)

REGISTRATION_TOKEN_EXPIRE_MINUTES = int(
    os.getenv("REGISTRATION_TOKEN_EXPIRE_MINUTES", "15")
)

ENROLLMENT_TOKEN_EXPIRE_MINUTES = int(
    os.getenv("ENROLLMENT_TOKEN_EXPIRE_MINUTES", "10")
)

TWO_FACTOR_ENCRYPTION_KEY = os.getenv(
    "TWO_FACTOR_ENCRYPTION_KEY"
)


if not JWT_SECRET or len(JWT_SECRET) < 32:
    raise RuntimeError(
        "JWT_SECRET must contain at least 32 characters."
    )

if TOKEN_EXPIRE_MINUTES <= 0:
    raise RuntimeError(
        "ACCESS_TOKEN_EXPIRE_MINUTES must be greater than zero."
    )

if PENDING_2FA_EXPIRE_MINUTES <= 0:
    raise RuntimeError(
        "PENDING_2FA_EXPIRE_MINUTES must be greater than zero."
    )

if REGISTRATION_TOKEN_EXPIRE_MINUTES <= 0:
    raise RuntimeError(
        "REGISTRATION_TOKEN_EXPIRE_MINUTES must be greater than zero."
    )

if ENROLLMENT_TOKEN_EXPIRE_MINUTES <= 0:
    raise RuntimeError(
        "ENROLLMENT_TOKEN_EXPIRE_MINUTES must be greater than zero."
    )

if not TWO_FACTOR_ENCRYPTION_KEY:
    raise RuntimeError(
        "TWO_FACTOR_ENCRYPTION_KEY is missing. "
        "Configure a valid Fernet key in .env."
    )


try:
    encryption = Fernet(
        TWO_FACTOR_ENCRYPTION_KEY.encode("utf-8")
    )

except (ValueError, TypeError):
    raise RuntimeError(
        "TWO_FACTOR_ENCRYPTION_KEY is invalid. "
        "Generate a valid Fernet key."
    )


# =========================================================
# COMMON TOKEN HELPERS
# =========================================================

def utc_now() -> datetime:
    """Return the current UTC datetime."""

    return datetime.now(timezone.utc)


def create_typed_token(
    subject: str | int,
    token_type: str,
    expires_minutes: int,
    extra_claims: dict | None = None,
) -> str:
    """
    Create a JWT with a specific token type.

    Each authentication stage uses a different token type.
    """

    if expires_minutes <= 0:
        raise ValueError(
            "Token expiration must be greater than zero."
        )

    now = utc_now()

    payload = {
        "sub": str(subject),
        "iat": now,
        "exp": now + timedelta(minutes=expires_minutes),
        "type": token_type,
        "jti": secrets.token_urlsafe(32),
    }

    if extra_claims:
        reserved = {"sub", "iat", "exp", "type", "jti"}

        for key, value in extra_claims.items():
            if key not in reserved:
                payload[key] = value

    return jwt.encode(
        payload,
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


def decode_typed_token(
    token: str,
    expected_type: str,
) -> dict | None:
    """
    Decode a JWT and verify its expected token type.
    """

    if not token or not expected_type:
        return None

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
        )

        if payload.get("type") != expected_type:
            return None

        if not payload.get("sub"):
            return None

        if not payload.get("jti"):
            return None

        return payload

    except (JWTError, ValueError, TypeError):
        return None


# =========================================================
# PASSWORD HASHING
# =========================================================

password_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""

    if not password:
        raise ValueError("Password cannot be empty.")

    return password_context.hash(password)


def verify_password(
    plain_password: str,
    password_hash: str,
) -> bool:
    """Verify a password against its stored hash."""

    if not plain_password or not password_hash:
        return False

    try:
        return password_context.verify(
            plain_password,
            password_hash,
        )

    except (ValueError, TypeError):
        return False


# =========================================================
# FINAL ACCESS TOKEN
# =========================================================

def create_access_token(
    user_id: int,
    expires_minutes: int | None = None,
) -> str:
    """
    Create the final authenticated access token.

    Only this token type is accepted by protected
    application endpoints.
    """

    duration = (
        expires_minutes
        if expires_minutes is not None
        else TOKEN_EXPIRE_MINUTES
    )

    return create_typed_token(
        subject=user_id,
        token_type="access",
        expires_minutes=duration,
    )


def decode_access_token(token: str) -> int | None:
    """
    Decode and validate a final access token.

    Registration, enrollment and pending 2FA tokens
    are rejected.
    """

    payload = decode_typed_token(
        token,
        expected_type="access",
    )

    if payload is None:
        return None

    try:
        return int(payload["sub"])

    except (ValueError, TypeError, KeyError):
        return None


# =========================================================
# PENDING REGISTRATION TOKEN
# =========================================================

def create_registration_token(
    pending_registration_id: int,
) -> str:
    """
    Create a temporary token for email verification.

    This token must never authorize dashboard access.
    """

    return create_typed_token(
        subject=pending_registration_id,
        token_type="pending_registration",
        expires_minutes=REGISTRATION_TOKEN_EXPIRE_MINUTES,
    )


def decode_registration_token(
    token: str,
) -> int | None:
    """Validate a pending registration token."""

    payload = decode_typed_token(
        token,
        expected_type="pending_registration",
    )

    if payload is None:
        return None

    try:
        return int(payload["sub"])

    except (ValueError, TypeError, KeyError):
        return None


def decode_registration_payload(
    token: str,
) -> dict | None:
    """Return the validated registration token payload."""

    return decode_typed_token(
        token,
        expected_type="pending_registration",
    )


# =========================================================
# EMAIL VERIFICATION TOKEN
# =========================================================

def create_email_verification_token(
    pending_registration_id: int,
) -> str:
    """
    Create a temporary token for email verification.

    The route must also check the OTP stored in the
    pending registration record.
    """

    return create_typed_token(
        subject=pending_registration_id,
        token_type="email_verification",
        expires_minutes=REGISTRATION_TOKEN_EXPIRE_MINUTES,
    )


def decode_email_verification_token(
    token: str,
) -> int | None:
    """Validate an email verification token."""

    payload = decode_typed_token(
        token,
        expected_type="email_verification",
    )

    if payload is None:
        return None

    try:
        return int(payload["sub"])

    except (ValueError, TypeError, KeyError):
        return None


# =========================================================
# TWO-FACTOR ENROLLMENT TOKEN
# =========================================================

def create_enrollment_token(
    pending_registration_id: int,
) -> str:
    """
    Create a temporary token after email verification.

    This token only authorizes registration 2FA enrollment.
    It is not a final authenticated access token.
    """

    return create_typed_token(
        subject=pending_registration_id,
        token_type="2fa_enrollment",
        expires_minutes=ENROLLMENT_TOKEN_EXPIRE_MINUTES,
    )


def decode_enrollment_token(
    token: str,
) -> int | None:
    """Validate a temporary 2FA enrollment token."""

    payload = decode_typed_token(
        token,
        expected_type="2fa_enrollment",
    )

    if payload is None:
        return None

    try:
        return int(payload["sub"])

    except (ValueError, TypeError, KeyError):
        return None


def decode_enrollment_payload(
    token: str,
) -> dict | None:
    """Return the validated enrollment token payload."""

    return decode_typed_token(
        token,
        expected_type="2fa_enrollment",
    )


# =========================================================
# TEMPORARY LOGIN 2FA TOKEN
# =========================================================

def create_pending_2fa_token(
    user_id: int,
    method: str | None = None,
) -> str:
    """
    Create a short-lived token after primary authentication.

    This token only authorizes login 2FA verification.
    """

    extra_claims = {}

    if method in ("totp", "email"):
        extra_claims["method"] = method

    return create_typed_token(
        subject=user_id,
        token_type="pending_2fa",
        expires_minutes=PENDING_2FA_EXPIRE_MINUTES,
        extra_claims=extra_claims,
    )


def decode_pending_2fa_token(
    token: str,
) -> int | None:
    """Validate a temporary login 2FA token."""

    payload = decode_typed_token(
        token,
        expected_type="pending_2fa",
    )

    if payload is None:
        return None

    try:
        return int(payload["sub"])

    except (ValueError, TypeError, KeyError):
        return None


def decode_pending_2fa_payload(
    token: str,
) -> dict | None:
    """
    Return the validated pending login 2FA payload.

    Useful for checking the requested authentication method
    and token identifier.
    """

    return decode_typed_token(
        token,
        expected_type="pending_2fa",
    )


# =========================================================
# EMAIL OTP
# =========================================================

def generate_email_otp() -> str:
    """Generate a cryptographically secure six-digit OTP."""

    return f"{secrets.randbelow(1_000_000):06d}"


def hash_otp(otp: str) -> str:
    """Store an HMAC digest instead of storing the OTP itself."""

    if (
        not otp
        or len(otp) != 6
        or not otp.isdigit()
    ):
        raise ValueError(
            "OTP must contain exactly six digits."
        )

    return hmac.new(
        JWT_SECRET.encode("utf-8"),
        otp.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_otp(
    submitted_otp: str,
    stored_hash: str,
) -> bool:
    """Compare a submitted OTP with its stored HMAC digest."""

    if not submitted_otp or not stored_hash:
        return False

    if (
        len(submitted_otp) != 6
        or not submitted_otp.isdigit()
    ):
        return False

    try:
        expected_hash = hash_otp(submitted_otp)

        return hmac.compare_digest(
            expected_hash,
            stored_hash,
        )

    except (ValueError, TypeError):
        return False


# =========================================================
# GOOGLE AUTHENTICATOR / TOTP
# =========================================================

def generate_totp_secret() -> str:
    """Generate a new authenticator secret."""

    return pyotp.random_base32()


def get_totp_provisioning_uri(
    secret: str,
    email: str,
    issuer: str = "IDPS Shield",
) -> str:
    """Generate the authenticator provisioning URI."""

    totp = pyotp.TOTP(secret)

    return totp.provisioning_uri(
        name=email,
        issuer_name=issuer,
    )


def get_totp_matching_step(
    secret: str,
    submitted_code: str,
    valid_window: int = 1,
) -> int | None:
    """
    Return the matching TOTP time step.

    The caller should compare the result with the last
    successfully used step to prevent replay.
    """

    if (
        not submitted_code
        or len(submitted_code) != 6
        or not submitted_code.isdigit()
    ):
        return None

    try:
        totp = pyotp.TOTP(secret)

        current_step = int(
            utc_now().timestamp() // totp.interval
        )

        for step in range(
            current_step - valid_window,
            current_step + valid_window + 1,
        ):
            expected_code = totp.generate_otp(step)

            if hmac.compare_digest(
                expected_code,
                submitted_code,
            ):
                return step

        return None

    except (ValueError, TypeError):
        return None


def verify_totp(
    secret: str,
    submitted_code: str,
) -> bool:
    """
    Verify a Google Authenticator code.

    Use get_totp_matching_step() in authentication routes
    when replay protection is required.
    """

    return (
        get_totp_matching_step(
            secret,
            submitted_code,
            valid_window=1,
        )
        is not None
    )


# =========================================================
# TOTP SECRET ENCRYPTION
# =========================================================

def encrypt_totp_secret(secret: str) -> str:
    """Encrypt the authenticator secret before database storage."""

    if not secret:
        raise ValueError(
            "Authenticator secret cannot be empty."
        )

    encrypted = encryption.encrypt(
        secret.encode("utf-8")
    )

    return encrypted.decode("utf-8")


def decrypt_totp_secret(
    encrypted_secret: str,
) -> str:
    """Decrypt the authenticator secret for verification."""

    if not encrypted_secret:
        raise ValueError(
            "Authenticator secret is missing."
        )

    try:
        decrypted = encryption.decrypt(
            encrypted_secret.encode("utf-8")
        )

        return decrypted.decode("utf-8")

    except (InvalidToken, ValueError, TypeError):
        raise ValueError(
            "Unable to decrypt authenticator secret."
        )
