# ─────────────────────────────────────────────────────────────────────────────
# api/views.py — Authentication Gauntlet Lab
#
# Wrap-Up Comparison Table (Reporter fills this in at the end of the lab):
#
# | Scheme  | Credential Location | Stateful? | Token Expiry | Revocable? |
# |---------|---------------------|-----------|--------------|------------|
# | Basic   |   No                  |   Yes        | Yes             |     No       |
# | Session |   Yes                |         Yes  |    No          |         No   |
# | Token   |     Yes                |     Yes      |       Yes       |       No     |
# | JWT     |       No              |    No       |     Yes         |       No     |
#
# ─────────────────────────────────────────────────────────────────────────────

from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import (
    BasicAuthentication,
    SessionAuthentication,
    TokenAuthentication,
)
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.response import Response


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 — Basic Authentication
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@authentication_classes([BasicAuthentication])
@permission_classes([IsAuthenticated])
def basic_auth_view(request):
    auth_header = request.META.get('HTTP_AUTHORIZATION')
    print(f"Incoming Header: {auth_header}")

    # Reporter — Phase 1 challenge answers:
    # Q1 answer (header format for admin:admin123): admin:admin123 which is username:password format.
    # Q2 answer (what happens without credentials): Request will be rejected
    # with 401 Unauthorized; over plain HTTP the header is sent in the clear
    # (Base64 is not encryption), so credentials can be intercepted.

    return Response({"message": "Check your terminal!"})


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2 — Session Authentication
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@authentication_classes([SessionAuthentication])
@permission_classes([IsAuthenticated])
def session_auth_view(request):
    # Reporter — Phase 2 challenge answers:
    # Q1 answer (effect of deleting the session cookie):
    # When the `sessionid` cookie is deleted from the browser, the browser stops sending the session key 
    # with requests. As a result, the server (Django) cannot link the request to any record in its 
    # server-side session database (django_session), causing the user to be logged out. The session 
    # record still exists on the server, but the browser has lost its pointer to it.
    #
    # Synthesis answer (how session fixation works):
    # Manually re-adding the original `sessionid` cookie logs the user back in instantly, demonstrating that 
    # session authentication relies entirely on the browser presenting a valid session key, enabling session hijacking 
    # if stolen. In a session fixation attack, an attacker forces or "fixes" a known session ID in the victim's 
    # browser before they log in. Once the victim logs in, that fixed session ID becomes authenticated, allowing 
    # the attacker (who already knows the fixed ID) to hijack the active session and bypass authentication.

    return Response({"message": "Session authenticated.", "user": request.user.username})


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3 — Token Authentication (Opaque)
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def token_auth_view(request):
    # Reporter — Phase 3 challenge answers:
    # Q1 answer (status code when token is tampered):
    # 401 Unauthorized — the server looked up the tampered token string in the
    # database, found no matching record, and rejected the request with
    # {"detail": "Invalid token."}
#
# Q2 answer (algorithm used to hash admin's password in the DB):
# pbkdf2_sha256 — Django hashes passwords using PBKDF2 with SHA-256 and
# 600000 iterations. "admin123" is never stored as plaintext; only the
# hash exists in the database so a breach does not expose the real password.
#
# Synthesis answer (how to revoke a token):
# To permanently invalidate a stolen opaque token, an admin must delete
# that token row from the database. A JWT cannot be revoked the same way
# because the server never stores it; you must wait for expiry or maintain
# a server-side blocklist, which reintroduces statefulness.

    return Response({"message": "Token authenticated.", "user": request.user.username})




@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def jwt_protected_view(request):
    # Reporter — Phase 4 challenge answers:
    # Q1 answer (fields found in the decoded payload):
    # Q2 answer (what happens when the signature is tampered):
    # Synthesis answer (JWT revocation challenge and workaround):
    
    
    # ─────────────────────────────────────────────────────────────────────────────
    # PHASE 4 — JSON Web Tokens (JWT)
    # Q1 answer (fields found in the decoded payload):
    # user_id ("1") identifies the user; exp is the expiry timestamp; also present: iat, jti, token_type.

    # Q2 answer (what happens when the signature is tampered):
    # The server recomputes the HMAC-SHA256 signature using its SECRET_KEY and rejects
    # any token whose signature doesn't match — no database lookup needed.

    # Synthesis answer (JWT revocation challenge and workaround):
    # Because JWTs are stateless, revoking one requires a server-side blocklist of jti
    # values — unlike opaque tokens which are simply deleted from the database.

    # ─────────────────────────────────────────────────────────────────────────────

    return Response({"message": "JWT authenticated.", "user": request.user.username})
