# ─────────────────────────────────────────────────────────────────────────────
# api/views.py — Authentication Gauntlet Lab
#
# Wrap-Up Comparison Table (Reporter fills this in at the end of the lab):
#
# | Scheme  | Credential Location | Stateful? | Token Expiry | Revocable? |
# |---------|---------------------|-----------|--------------|------------|
# | Basic   |                     |           |              |            |
# | Session |                     |           |              |            |
# | Token   |                     |           |              |            |
# | JWT     |                     |           |              |            |
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
    # Extract the raw Authorization header and print it to the terminal.
    # Hint: the header key in request.META is 'HTTP_AUTHORIZATION'.
    auth_header = request.META.get('HTTP_AUTHORIZATION')
    print(f"Incoming Header: {auth_header}")

    # Reporter — Phase 1 challenge answers:
    # Q1 answer (header format for admin:admin123): admin:admin123
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
    # Synthesis answer (how session fixation works):

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
    # Q2 answer (algorithm used to hash admin's password in the DB):
    # Synthesis answer (how to revoke a token):

    return Response({"message": "Token authenticated.", "user": request.user.username})


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

@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def jwt_protected_view(request):
    # Reporter — Phase 4 challenge answers:
    # Q1 answer (fields found in the decoded payload):
    # Q2 answer (what happens when the signature is tampered):
    # Synthesis answer (JWT revocation challenge and workaround):

    return Response({"message": "JWT authenticated.", "user": request.user.username})
