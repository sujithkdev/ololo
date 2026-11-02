# server/auth.py — Multi-user JWT auth + RBAC
"""
Roles:
  admin   — full access (all endpoints + clear + user management)
  analyst — read-only dashboard + can send C2 commands
  viewer  — read-only dashboard, no commands

Agents authenticate with the shared API_KEY header (unchanged).
Dashboard users authenticate with username/password → receive JWT.

Default admin account: admin / change-me-now
Create users via:  POST /auth/users  (admin only)
"""
import hashlib, hmac, json, os, time, threading, secrets
from functools import wraps
from flask import request, jsonify, g
from behedr_server.config import JWT_SECRET, JWT_EXPIRY, DATA_DIR

try:
    import jwt as _jwt          # PyJWT — pip install PyJWT
    _PYJWT = True
except ImportError:
    _PYJWT = False
    import base64 as _base64    # fallback only — install PyJWT in production

# ── User store (JSON file — swap for DB table in full production) ─────────────
_USERS_FILE = os.path.join(DATA_DIR, "users.json")
_users_lock = threading.Lock()


def _hash_pw(password: str) -> str:
    """SHA-256 with per-user salt, stored as salt:hash."""
    salt = secrets.token_hex(16)
    h    = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{h}"


def _verify_pw(password: str, stored: str) -> bool:
    try:
        salt, h = stored.split(":", 1)
        return hmac.compare_digest(
            hashlib.sha256((salt + password).encode()).hexdigest(), h)
    except Exception:
        return False


def _load_users() -> dict:
    if os.path.exists(_USERS_FILE):
        try:
            with open(_USERS_FILE, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    # Bootstrap default admin
    default = {
        "admin": {
            "password": _hash_pw("change-me-now"),
            "role":     "admin",
            "created":  int(time.time()),
        }
    }
    _save_users(default)
    return default


def _save_users(users: dict):
    tmp = _USERS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)
    os.replace(tmp, _USERS_FILE)


def get_users():
    with _users_lock:
        return _load_users()


def create_user(username: str, password: str, role: str = "analyst") -> bool:
    if role not in ("admin", "analyst", "viewer"):
        return False
    # ── Password policy enforcement ───────────────────────────────────────
    try:
        from behedr_server.password_policy import validate_and_check_password, record_password_change
        valid, err = validate_and_check_password(username, password)
        if not valid:
            print(f"[AUTH] create_user rejected '{username}': {err}")
            return False
    except Exception as _pe:
        print(f"[AUTH] password_policy error (non-fatal, allowing): {_pe}")
    with _users_lock:
        users = _load_users()
        if username in users:
            return False
        users[username] = {
            "password": _hash_pw(password),
            "role":     role,
            "created":  int(time.time()),
        }
        _save_users(users)
    # Record in password history (after save so history stays in sync)
    try:
        from behedr_server.password_policy import record_password_change
        record_password_change(username, password)
    except Exception:
        pass
    return True


def delete_user(username: str) -> bool:
    with _users_lock:
        users = _load_users()
        if username not in users or username == "admin":
            return False
        del users[username]
        _save_users(users)
    return True


def change_password(username: str, new_password: str) -> tuple:
    """
    Change a user's password with full policy enforcement.
    Returns (success: bool, error_message: str).
    """
    # ── Policy: strength + history ────────────────────────────────────────
    try:
        from behedr_server.password_policy import validate_and_check_password, record_password_change
        valid, err = validate_and_check_password(username, new_password)
        if not valid:
            return False, err
    except ImportError:
        pass   # policy module missing — allow

    with _users_lock:
        users = _load_users()
        if username not in users:
            return False, "User not found"
        users[username]["password"] = _hash_pw(new_password)
        users[username]["must_change_password"] = False
        _save_users(users)

    # Record in password history
    try:
        from behedr_server.password_policy import record_password_change
        record_password_change(username, new_password)
    except Exception:
        pass

    return True, ""


def get_password_policy() -> dict:
    """Return current password policy for the API /auth/policy endpoint."""
    try:
        from behedr_server.password_policy import get_password_policy as _gpp
        return _gpp()
    except ImportError:
        return {}


def must_change_password(username: str) -> bool:
    """Return True if the user must change their password on next login."""
    with _users_lock:
        users = _load_users()
    return users.get(username, {}).get("must_change_password", False)


def authenticate(username: str, password: str):
    """Returns (role, token) or raises ValueError."""
    with _users_lock:
        users = _load_users()
    user = users.get(username)
    if not user or not _verify_pw(password, user["password"]):
        raise ValueError("Invalid credentials")
    token = _make_jwt(username, user["role"])
    return user["role"], token


# ── JWT (HS256) — uses PyJWT when available, safe fallback otherwise ──────────
# Install PyJWT for production:  pip install PyJWT

def _make_jwt(username: str, role: str) -> str:
    now = int(time.time())
    payload = {
        "sub":  username,
        "role": role,
        "iat":  now,
        "exp":  now + JWT_EXPIRY,
    }
    if _PYJWT:
        # PyJWT handles encoding, signing, and padding correctly
        return _jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    # ── Safe fallback (no external deps) ─────────────────────────────────
    # Uses hmac.digest() — stdlib Python 3.7+ — no hand-rolled call
    header_b64  = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload_b64 = _b64url(json.dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = _b64url(hmac.digest(JWT_SECRET.encode(), signing_input, "sha256"))
    return f"{header_b64}.{payload_b64}.{sig}"


def _b64url(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _decode_jwt(token: str) -> dict:
    """Verify and decode JWT. Raises ValueError on any failure."""
    if _PYJWT:
        try:
            claims = _jwt.decode(
                token, JWT_SECRET,
                algorithms=["HS256"],
                options={"require": ["exp", "sub", "role"]},
            )
            return claims
        except _jwt.ExpiredSignatureError:
            raise ValueError("Token expired")
        except _jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid token: {e}")
    # ── Safe fallback ─────────────────────────────────────────────────────
    try:
        import base64
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Malformed token")
        header_b64, payload_b64, sig = parts
        signing_input = f"{header_b64}.{payload_b64}".encode()
        expected_sig = _b64url(
            hmac.digest(JWT_SECRET.encode(), signing_input, "sha256"))
        if not hmac.compare_digest(sig, expected_sig):
            raise ValueError("Bad signature")
        pad    = 4 - len(payload_b64) % 4
        claims = json.loads(
            base64.urlsafe_b64decode(payload_b64 + "=" * pad))
        if claims.get("exp", 0) < time.time():
            raise ValueError("Token expired")
        return claims
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f"Invalid token: {e}")


# ── Flask decorators ──────────────────────────────────────────────────────────

def require_jwt(min_role: str = "viewer"):
    """Decorator: validate JWT from Authorization: Bearer <token> header."""
    ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}

    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return jsonify({"error": "Missing or invalid Authorization header"}), 401
            token = auth[7:]
            try:
                claims = _decode_jwt(token)
            except ValueError as e:
                return jsonify({"error": str(e)}), 401
            user_rank = ROLE_RANK.get(claims.get("role", ""), -1)
            min_rank  = ROLE_RANK.get(min_role, 0)
            if user_rank < min_rank:
                return jsonify({"error": f"Requires role '{min_role}' or higher"}), 403
            g.user     = claims["sub"]
            g.role     = claims["role"]
            return f(*args, **kwargs)
        return wrapped
    return decorator


def require_agent_key(f):
    """Decorator: validate shared agent API key (unchanged from before)."""
    from behedr_server.config import API_KEY
    @wraps(f)
    def wrapped(*args, **kwargs):
        if request.headers.get("API-Key", "") != API_KEY:
            return jsonify({"error": "Unauthorized — wrong or missing API-Key"}), 401
        return f(*args, **kwargs)
    return wrapped
