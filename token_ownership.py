#!/usr/bin/env python3
"""Token-owner verification for the token-submission form.

A token's on-chain `owner` (from `rpc.get_token_info`) is the deploying
wallet's **account spend public key**.  The Beldex CLI wallet can sign an
arbitrary short string with exactly that key:

    [wallet]: sign_value <challenge>
    SigV1....

(Unquoted: the CLI splits commands on spaces and never strips quotes, so
quoting would sign the quote characters too.  Challenges are generated
space-free so they survive that split as a single argument.)

`wallet2::sign()` does `keccak(data)` -> `crypto::generate_signature(hash,
spend_pubkey, spend_seckey)` and returns ``"SigV1" + monero_base58(sig)``.  So
checking a submitter really owns a token is just `crypto::check_signature()`
against the owner key already published on-chain — no wallet, no wallet-rpc and
no daemon call beyond the token lookup the form already does.

This module is a self-contained port of the pieces that requires:

  * keccak-256 (``cn_fast_hash``)
  * Monero's block-based base58
  * enough ed25519 arithmetic for ``check_signature``

plus the stateless challenge/token helpers the routes use.  `check_signature`
is verified against the 512 official ``tests/crypto/tests.txt`` vectors from the
core repo (see ``test_token_ownership.py``).

Everything here is pure Python and dependency-free on purpose: the explorer runs
under uwsgi with several worker processes and no shared state, and we do not
want ownership checks to hinge on a particular libsodium build.
"""

import hashlib
import hmac
import os
import secrets
import struct
import sys
import time

# --------------------------------------------------------------------- keccak

_KECCAK_ROUND_CONSTANTS = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_KECCAK_ROTATIONS = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
]
_MASK64 = (1 << 64) - 1


def _keccak_f1600(state):
    for rc in _KECCAK_ROUND_CONSTANTS:
        # theta
        c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        for x in range(5):
            d = c[(x - 1) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & _MASK64)
            for y in range(5):
                state[x][y] ^= d
        # rho + pi
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                r = _KECCAK_ROTATIONS[x][y]
                b[y][(2 * x + 3 * y) % 5] = ((state[x][y] << r) | (state[x][y] >> (64 - r))) & _MASK64 \
                    if r else state[x][y]
        # chi
        for x in range(5):
            for y in range(5):
                state[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y] & _MASK64) & b[(x + 2) % 5][y])
        # iota
        state[0][0] ^= rc
    return state


def _keccak256_pure(data):
    rate = 136  # 1088 bits, keccak-256
    state = [[0] * 5 for _ in range(5)]
    # Original Keccak padding (0x01), not the SHA-3 variant (0x06).
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] |= 0x80

    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            lane = struct.unpack_from('<Q', block, i * 8)[0]
            state[i % 5][i // 5] ^= lane
        _keccak_f1600(state)

    out = bytearray()
    for i in range(4):  # 32 bytes
        out += struct.pack('<Q', state[i % 5][i // 5])
    return bytes(out)


def _pick_keccak():
    """Prefer a C keccak if one is installed; fall back to the pure-Python one."""
    try:  # python3-sha3 / pysha3
        import sha3
        if sha3.keccak_256(b'').hexdigest() == \
                'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470':
            return lambda data: sha3.keccak_256(data).digest()
    except Exception:
        pass
    try:  # pycryptodome
        from Crypto.Hash import keccak as _k
        if _k.new(digest_bits=256, data=b'').hexdigest() == \
                'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470':
            return lambda data: _k.new(digest_bits=256, data=data).digest()
    except Exception:
        pass
    return _keccak256_pure


keccak256 = _pick_keccak()


def cn_fast_hash(data):
    """Monero's cn_fast_hash: plain keccak-256."""
    return keccak256(data)


# ---------------------------------------------------------------- base58 (XMR)

_B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}
# How many base58 chars encode a block of N bytes (index = byte count).
_B58_ENCODED_BLOCK_SIZES = [0, 2, 3, 5, 6, 7, 9, 10, 11]
_B58_FULL_BLOCK_SIZE = 8
_B58_FULL_ENCODED_BLOCK_SIZE = 11


class Base58Error(ValueError):
    pass


def monero_b58_decode(text):
    """Decode Monero's block-based base58 (NOT the Bitcoin variant)."""
    if not text:
        return b''
    full_blocks, last_size = divmod(len(text), _B58_FULL_ENCODED_BLOCK_SIZE)
    if last_size not in _B58_ENCODED_BLOCK_SIZES:
        raise Base58Error('invalid base58 length')

    out = bytearray()
    for i in range(full_blocks + (1 if last_size else 0)):
        chunk = text[i * _B58_FULL_ENCODED_BLOCK_SIZE:(i + 1) * _B58_FULL_ENCODED_BLOCK_SIZE]
        size = _B58_FULL_BLOCK_SIZE if len(chunk) == _B58_FULL_ENCODED_BLOCK_SIZE \
            else _B58_ENCODED_BLOCK_SIZES.index(len(chunk))
        value = 0
        for ch in chunk:
            digit = _B58_INDEX.get(ch)
            if digit is None:
                raise Base58Error('invalid base58 character')
            value = value * 58 + digit
        if value >= 1 << (8 * size):
            raise Base58Error('base58 block overflow')
        out += value.to_bytes(size, 'big')
    return bytes(out)


# --------------------------------------------------------------------- ed25519
# Just enough of the group law for check_signature. Points are kept in extended
# coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z, xy = T/Z.

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)  # sqrt(-1)

_BASE_Y = 4 * pow(5, _P - 2, _P) % _P
_BASE_X = None  # filled in below


def _point_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (2 * t1 * t2 * _D) % _P
    d = (2 * z1 * z2) % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return ((e * f) % _P, (g * h) % _P, (f * g) % _P, (e * h) % _P)


def _point_double(p):
    return _point_add(p, p)


def _scalarmult(p, e):
    q = (0, 1, 1, 0)  # identity
    while e > 0:
        if e & 1:
            q = _point_add(q, p)
        p = _point_double(p)
        e >>= 1
    return q


def _recover_x(y, sign):
    """x from y on -x^2 + y^2 = 1 + d x^2 y^2, matching ge_frombytes_vartime."""
    if y >= _P:
        return None
    yy = (y * y) % _P
    u = (yy - 1) % _P
    v = (_D * yy + 1) % _P
    # x = u v^3 (u v^7)^((p-5)/8)
    v3 = (v * v % _P) * v % _P
    x = (u * v3) % _P * pow(u * v3 % _P * v3 % _P * v % _P, (_P - 5) // 8, _P) % _P
    vxx = (v * x % _P) * x % _P
    if (vxx - u) % _P != 0:
        if (vxx + u) % _P != 0:
            return None
        x = x * _I % _P
    if x == 0 and sign:
        return None
    if x % 2 != sign:
        x = _P - x
    return x


def _decode_point(data):
    """Decompress a 32-byte ed25519 point, or None if it is not on the curve."""
    if len(data) != 32:
        return None
    value = int.from_bytes(data, 'little')
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _encode_point(p):
    x, y, z, _t = p
    zinv = pow(z, _P - 2, _P)
    x = x * zinv % _P
    y = y * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, 'little')


_BASE_X = _recover_x(_BASE_Y, 0)
_BASE_POINT = (_BASE_X, _BASE_Y, 1, _BASE_X * _BASE_Y % _P)

# ge_tobytes() of the identity: y = 1, x = 0.
_INFINITY = b'\x01' + b'\x00' * 31


def _sc_check(data):
    """0 if the scalar is canonical (< l), like Monero's sc_check()."""
    return int.from_bytes(data, 'little') < _L


def _hash_to_scalar(data):
    return int.from_bytes(cn_fast_hash(data), 'little') % _L


def check_signature(prefix_hash, pub, sig):
    """crypto::check_signature() — Schnorr over ed25519, Monero flavour.

    prefix_hash: 32 bytes, pub: 32 bytes, sig: 64 bytes (c || r).
    """
    if len(prefix_hash) != 32 or len(pub) != 32 or len(sig) != 64:
        return False

    point = _decode_point(pub)
    if point is None:
        return False

    c_bytes, r_bytes = sig[:32], sig[32:]
    if not _sc_check(c_bytes) or not _sc_check(r_bytes):
        return False
    c = int.from_bytes(c_bytes, 'little')
    r = int.from_bytes(r_bytes, 'little')
    if c == 0:
        return False

    # comm = c*A + r*G
    comm = _point_add(_scalarmult(point, c), _scalarmult(_BASE_POINT, r))
    comm_bytes = _encode_point(comm)
    if comm_bytes == _INFINITY:
        return False

    expected = _hash_to_scalar(prefix_hash + pub + comm_bytes)
    return (expected - c) % _L == 0


# ------------------------------------------------------------- SigV1 messages

SIG_MAGIC = 'SigV1'


def address_spend_key(address):
    """Spend public key (hex) embedded in a Beldex address, or None.

    Layout after base58: [varint prefix][spend 32][view 32][payment id 8 if
    integrated][checksum 4], checksum = keccak(everything before it)[:4].
    Works for standard, subaddress and integrated addresses — note a
    subaddress carries its OWN spend key, so it will not match a token owner.
    """
    try:
        raw = monero_b58_decode((address or '').strip())
    except Base58Error:
        return None
    if len(raw) < 69:
        return None
    i = 0
    while i < len(raw) and raw[i] & 0x80:   # skip the varint network prefix
        i += 1
    i += 1
    body, checksum = raw[:-4], raw[-4:]
    if cn_fast_hash(body)[:4] != checksum:
        return None
    spend = raw[i:i + 32]
    return spend.hex() if len(spend) == 32 else None


def message_variants(message):
    """Every string the wallet may actually have signed for `message`.

    The CLI tokenises a command with a plain space split and no quote handling
    (`boost::split(..., is_any_of(" "))` in epee's console_handler), so
    `sign_value "abc"` signs `"abc"` *with* the quote characters. Users copy
    quoted examples all the time, so accept the quoted forms as well: each one
    still commits to the same challenge, so nothing is weakened.
    """
    variants = [message]
    for q in ('"', "'"):
        variants.append(q + message + q)
    return variants


def verify_signed_message(message, owner_pubkey_hex, signature):
    """True iff `signature` is a wallet `sign`/`sign_value` signature over
    `message` made by the key `owner_pubkey_hex` (the token's on-chain owner).

    Returns (ok, reason); reason is a short user-facing string when ok is False.
    """
    if not isinstance(signature, str):
        return False, 'Signature is missing.'
    signature = signature.strip()
    if not signature:
        return False, 'Signature is missing.'
    if not signature.startswith(SIG_MAGIC):
        return False, 'That does not look like a wallet signature (it should start with "SigV1").'

    try:
        owner = bytes.fromhex((owner_pubkey_hex or '').strip())
    except ValueError:
        return False, 'This token has no usable owner key on-chain.'
    if len(owner) != 32:
        return False, 'This token has no usable owner key on-chain.'

    try:
        raw = monero_b58_decode(signature[len(SIG_MAGIC):])
    except Base58Error:
        return False, 'The signature is malformed — copy the whole SigV1… string.'
    if len(raw) != 64:
        return False, 'The signature is malformed — copy the whole SigV1… string.'

    for candidate in message_variants(message):
        if check_signature(cn_fast_hash(candidate.encode('utf-8')), owner, raw):
            return True, ''
    return False, ('Signature does not match this token\'s owner key. Sign the exact challenge '
                   'with the wallet that deployed the token, using its main address '
                   '(sign_value with no account index).')


# ------------------------------------------------- challenges & grant tokens
# Both are stateless: an HMAC over the fields lets any worker process validate
# what another one issued, with no shared session store.

CHALLENGE_PREFIX = 'beldex-token-owner'
CHALLENGE_VERSION = 'v1'
TOKEN_VERSION = 'v1'

# The CLI only echoes a signed value back to the user when it is plain ASCII and
# <= 100 bytes (simple_wallet::sign_string); past that it prints "(N bytes)" and
# the owner is signing something they cannot read. So the challenge is kept
# short: it *displays* a 16-char prefix of the token id, while the MAC is
# computed over the full token id and owner key, leaving the binding as strong
# as it was when the whole id was in the text.
CHALLENGE_ID_CHARS = 16
CHALLENGE_MAC_CHARS = 20   # 80-bit truncated HMAC, verified server-side only
TOKEN_MAC_CHARS = 32       # never signed by a human, so no length pressure
CHALLENGE_MAX_BYTES = 100


def _mac(secret, *parts, chars=32):
    msg = '|'.join(parts).encode('utf-8')
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()[:chars]


def resolve_secret(configured):
    """Return the HMAC secret as bytes.

    A per-process random secret is only safe for a single-worker dev server, so
    warn loudly when one has to be invented: with several uwsgi workers a
    challenge issued by worker A would be rejected by worker B.
    """
    if configured:
        return configured.encode('utf-8') if isinstance(configured, str) else configured
    print('WARNING: config.token_verify_secret is unset; generating a per-process secret. '
          'Ownership verification will break across multiple workers — set it in local_config.py.',
          file=sys.stderr)
    return os.urandom(32)


def _challenge_mac(token_id, owner, visible, secret):
    """MAC over the *full* token id and owner plus the visible challenge text.

    The visible text carries only a 16-char token prefix (to stay under the
    wallet's 100-byte echo limit), so the full values are folded in here
    instead: two tokens sharing a prefix still get unforgeably distinct
    challenges.
    """
    return _mac(secret, token_id, owner or '', visible, chars=CHALLENGE_MAC_CHARS)


def make_challenge(token_id, owner, secret, now=None):
    """Build the exact string the owner must sign.

    Single line, no spaces (so it survives `sign_value`'s argument rejoining),
    plain ASCII and short enough that the wallet echoes it back, so the signer
    can read what they are agreeing to before approving it.
    """
    issued = int(now if now is not None else time.time())
    nonce = secrets.token_hex(4)
    visible = '|'.join([CHALLENGE_PREFIX, CHALLENGE_VERSION,
                        token_id[:CHALLENGE_ID_CHARS], str(issued), nonce])
    return visible + '|' + _challenge_mac(token_id, owner, visible, secret)


def check_challenge(challenge, token_id, owner, secret, ttl):
    """Validate a challenge we issued: shape, MAC, binding and freshness."""
    if not challenge or not isinstance(challenge, str):
        return False, 'Missing challenge — start the verification again.'
    parts = challenge.strip().split('|')
    if len(parts) != 6:
        return False, 'Malformed challenge — start the verification again.'
    prefix, version, c_token, issued, _nonce, mac = parts
    if prefix != CHALLENGE_PREFIX or version != CHALLENGE_VERSION:
        return False, 'Unrecognised challenge — start the verification again.'
    # The MAC covers the full token id and owner, so a mismatched binding fails
    # here even though only a prefix of the id is visible in the text.
    expected = _challenge_mac(token_id, owner, '|'.join(parts[:5]), secret)
    if not hmac.compare_digest(mac, expected):
        # A MAC failure can't tell "issued for another token" apart from
        # "forged", so only the clear-cut case gets the specific wording.
        if c_token != (token_id or '')[:CHALLENGE_ID_CHARS]:
            return False, 'This challenge belongs to a different token.'
        return False, ('This challenge is not valid for this token — it was issued for a '
                       'different token, or not issued by this explorer. Generate a new one.')
    try:
        issued = int(issued)
    except ValueError:
        return False, 'Malformed challenge — start the verification again.'
    if issued > time.time() + 60:
        return False, 'Malformed challenge — start the verification again.'
    if time.time() - issued > ttl:
        return False, 'This challenge has expired — request a new one.'
    return True, ''


def issue_token(token_id, owner, secret, ttl, now=None):
    """Short-lived proof that ownership was verified for this token."""
    expiry = int(now if now is not None else time.time()) + int(ttl)
    body = '|'.join([TOKEN_VERSION, token_id, owner, str(expiry)])
    return body + '|' + _mac(secret, body, chars=TOKEN_MAC_CHARS)


def diagnose(message, owner_pubkey_hex, signature):
    """Human-readable breakdown of why a proof did or did not verify.

    Support tool for "it says my signature doesn't match": tells you which stage
    failed instead of just that the whole thing did.
    """
    lines = []
    owner_hex = (owner_pubkey_hex or '').strip()
    try:
        owner = bytes.fromhex(owner_hex)
    except ValueError:
        owner = b''
    lines.append('owner key      : {} ({} hex chars)'.format(
        'usable' if len(owner) == 32 else 'UNUSABLE', len(owner_hex)))
    if len(owner) == 32:
        lines.append('owner on curve : {}'.format(_decode_point(owner) is not None))

    sig = (signature or '').strip()
    lines.append('signature magic: {}'.format('SigV1 ok' if sig.startswith(SIG_MAGIC) else 'MISSING'))
    raw = b''
    if sig.startswith(SIG_MAGIC):
        try:
            raw = monero_b58_decode(sig[len(SIG_MAGIC):])
            lines.append('signature bytes: {} (need 64)'.format(len(raw)))
        except Base58Error as e:
            lines.append('signature bytes: base58 error ({})'.format(e))

    if len(raw) == 64 and len(owner) == 32:
        matched = None
        for i, candidate in enumerate(message_variants(message)):
            if check_signature(cn_fast_hash(candidate.encode('utf-8')), owner, raw):
                matched = ['exact challenge', 'double-quoted challenge',
                           "single-quoted challenge"][i]
                break
        lines.append('match          : {}'.format(matched or 'NONE — signed by a different key, '
                                                  'or over a different string'))
    return '\n'.join(lines)


def check_token(token, token_id, owner, secret):
    """Validate a token issued by issue_token(). Returns (ok, reason)."""
    if not token or not isinstance(token, str):
        return False, 'Ownership has not been verified.'
    parts = token.strip().split('|')
    if len(parts) != 5:
        return False, 'Ownership verification is invalid — verify again.'
    version, t_token, t_owner, expiry, mac = parts
    if version != TOKEN_VERSION:
        return False, 'Ownership verification is invalid — verify again.'
    if not hmac.compare_digest(mac, _mac(secret, *parts[:4], chars=TOKEN_MAC_CHARS)):
        return False, 'Ownership verification is invalid — verify again.'
    if t_token != token_id or (owner and t_owner != owner):
        return False, 'Ownership was verified for a different token.'
    try:
        expiry = int(expiry)
    except ValueError:
        return False, 'Ownership verification is invalid — verify again.'
    if time.time() > expiry:
        return False, 'Ownership verification has expired — verify again.'
    return True, ''


if __name__ == '__main__':
    # Support helper:
    #   python3 token_ownership.py <owner_pubkey_hex> <challenge> <SigV1...>
    if len(sys.argv) != 4:
        print(__doc__.strip().splitlines()[0])
        print('usage: python3 token_ownership.py <owner_pubkey_hex> <challenge> <signature>')
        raise SystemExit(2)
    _owner, _challenge, _signature = sys.argv[1], sys.argv[2], sys.argv[3]
    print(diagnose(_challenge, _owner, _signature))
    ok, why = verify_signed_message(_challenge, _owner, _signature)
    print('result         : {}'.format('VERIFIED' if ok else why))
    raise SystemExit(0 if ok else 1)
