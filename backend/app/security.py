"""Request authentication between the add-on and the backend.

The add-on signs "<timestamp>.<raw body>" with a shared secret (HMAC-SHA256).
The timestamp window limits replay of captured requests.
"""
import hashlib
import hmac
import time

MAX_CLOCK_SKEW_SECONDS = 300


def verify_signature(body: bytes, timestamp: str, signature: str, secret: bytes) -> bool:
    """Checks that the request came from our add-on, was not changed, and is not too old."""
    try:
        sent_at = int(timestamp)
    except ValueError:
        return False
    if abs(time.time() - sent_at) > MAX_CLOCK_SKEW_SECONDS:
        return False
    expected = hmac.new(secret, timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    # Constant-time comparison so the signature can't be guessed byte by byte.
    return hmac.compare_digest(expected, signature)
