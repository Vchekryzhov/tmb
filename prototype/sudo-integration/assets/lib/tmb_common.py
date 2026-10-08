# PROTOTYPE shared TMB checks (throwaway): config, canonical payload, real
# ed25519 verification, atomic durable redemption, audit log.
# Test-only: keys/config/state live inside disposable containers.
import base64
import json
import os
import socket
import time

ETC = "/usr/local/tmb/etc"

REQUEST_ID_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
)
PAYLOAD_FIELDS = {
    "request_id": str,
    "hostname": str,
    "runas_user": str,
    "program": str,
    "argv": list,
    "issued_at": int,
    "expires_at": int,
}


def load_config():
    with open(os.path.join(ETC, "tmb.json")) as f:
        return json.load(f)


def audit(cfg, event, detail):
    # Audit log is prototype state surfaced by the matrix runner, not a product.
    line = "%.3f %s %s" % (time.time(), event, detail)
    with open(os.path.join(cfg["state_dir"], "audit.log"), "a") as f:
        f.write(line + "\n")


def canonical(payload) -> bytes:
    # Canonical form covered by the signature: sorted keys, compact separators.
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def envelope_to_b64(env) -> str:
    return base64.b64encode(json.dumps(env).encode()).decode()


def envelope_from_b64(b64):
    return json.loads(base64.b64decode(b64))


def verify_envelope(env, cfg, *, program=None, argv=None, runas_user=None):
    """Real verification, never bypassed. Returns (ok, reason, payload).

    program/argv=None skips the command match (hook (b) dispatcher derives the
    target command from the payload itself)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    p = env.get("payload") if isinstance(env, dict) else None
    if not isinstance(p, dict) or not isinstance(env.get("sig"), str):
        return False, "envelope: payload/sig malformed", None
    if set(p) != set(PAYLOAD_FIELDS):
        return False, "payload fields mismatch: %s" % sorted(p), None
    for key, typ in PAYLOAD_FIELDS.items():
        v = p[key]
        if typ is int:
            if not isinstance(v, int) or isinstance(v, bool):
                return False, "payload field %s must be an integer" % key, None
        elif typ is str:
            if not isinstance(v, str):
                return False, "payload field %s must be a string" % key, None
        else:  # list of strings
            if not isinstance(v, list) or not all(
                isinstance(x, str) for x in v
            ):
                return False, "payload field %s must be a string array" % key, None
    if not p["request_id"] or not set(p["request_id"]) <= REQUEST_ID_CHARS:
        return False, "request_id has invalid characters", None
    if not os.path.isabs(p["program"]):
        return False, "program path is not absolute", None

    # signature first (real crypto over the canonical payload bytes)
    try:
        with open(cfg["trusted_pubkey"], "rb") as f:
            pub = serialization.load_pem_public_key(f.read())
        if not isinstance(pub, Ed25519PublicKey):
            return False, "trusted key is not ed25519", None
        pub.verify(base64.b64decode(env["sig"], validate=True), canonical(p))
    except InvalidSignature:
        return False, "signature mismatch", None
    except Exception as e:  # bad base64, bad key file, ...
        return False, "signature verification error: %s" % e, None

    # host binding: config value must match both the permission and reality
    actual = socket.gethostname()
    if p["hostname"] != cfg["hostname"]:
        return False, "hostname mismatch: perm=%s cfg=%s" % (
            p["hostname"], cfg["hostname"]), None
    if actual != cfg["hostname"]:
        return False, "hostname mismatch: actual=%s cfg=%s" % (
            actual, cfg["hostname"]), None

    # run-as binding: config + (when supplied) the user sudo will really run as
    expected_runas = runas_user or cfg["runas_user"]
    if p["runas_user"] != expected_runas:
        return False, "runas mismatch: perm=%s expected=%s" % (
            p["runas_user"], expected_runas), None

    # exact requested command: program + ordered argv, no string folding
    if program is not None:
        if p["program"] != program:
            return False, "program mismatch: perm=%s actual=%s" % (
                p["program"], program), None
        if list(p["argv"]) != list(argv):
            return False, "argv mismatch: perm=%r actual=%r" % (
                p["argv"], list(argv)), None

    # freshness: TTL covers acceptance and start only
    now = int(time.time())
    if now < p["issued_at"]:
        return False, "issued_at is in the future", None
    if now > p["expires_at"]:
        return False, "expired (now=%d exp=%d)" % (now, p["expires_at"]), None
    return True, "ok", p


def verify_envelope_b64(b64, cfg, **kw):
    try:
        env = envelope_from_b64(b64)
    except Exception as e:
        return False, "envelope not decodable: %s" % e, None
    return verify_envelope(env, cfg, **kw)


def redeem(cfg, request_id):
    """Atomic durable one-time redemption BEFORE launch.

    O_CREAT|O_EXCL claim file + fsync(file) + fsync(dir). Survives restart;
    exactly one winner under races; launch failure never refunds."""
    d = os.path.join(cfg["state_dir"], "redeemed")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, request_id)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        audit(cfg, "redeem-deny", "%s already redeemed" % request_id)
        return False, "already redeemed"
    blob = json.dumps(
        {"request_id": request_id, "redeemed_at": time.time()}
    ).encode()
    os.write(fd, blob)
    os.fsync(fd)
    os.close(fd)
    dfd = os.open(d, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    audit(cfg, "redeem-ok", "%s consumed before launch" % request_id)
    return True, "redeemed"


def build_request(cfg, argv):
    # what the trusted signer displays to the human (exact request)
    return {
        "hostname": cfg["hostname"],
        "runas_user": cfg["runas_user"],
        "program": argv[0],
        "argv": list(argv[1:]),
    }
