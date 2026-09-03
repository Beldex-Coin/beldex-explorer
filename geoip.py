#!/usr/bin/env python3
"""IP geolocation for the master node distribution page.

Mirrors the mn-dashboard `server/geo.js` approach: the caller asks for a set of
IPs and gets the answers back, resolving whatever is missing in-line so the
page always renders with data rather than filling in later.

Lookups use ip-api.com's free batch endpoint (no API key, HTTP only, ~15
requests/minute, 100 IPs per request). Results are cached in process memory and
mirrored to disk on a best-effort basis, so a restart or a second uwsgi worker
starts warm instead of re-querying everything.

Two guards keep a page request from ever hanging:
  * a wall-clock budget, after which we return what we have;
  * ip-api's own X-Rl / X-Ttl rate-limit headers, which we obey rather than
    burning through the quota and getting the server's IP blocked.
Anything left over is simply picked up on the next request.
"""

import json
import os
import sys
import tempfile
import threading
import time
import zlib

import requests

_DIR = os.path.dirname(os.path.abspath(__file__))


def _pick_cache_dir():
    """First writable candidate wins.

    Under uwsgi the worker often runs as www-data while the checkout is owned
    by a human user, so the repo directory may not be writable. The disk cache
    is only an optimisation - lookups work regardless - but a writable location
    means results survive restarts. Set GEO_CACHE_DIR to choose one.
    """
    for d in (os.environ.get('GEO_CACHE_DIR'), _DIR, tempfile.gettempdir()):
        if d and os.path.isdir(d) and os.access(d, os.W_OK | os.X_OK):
            return d
    return None


CACHE_DIR = _pick_cache_dir()
CACHE_FILE = os.path.join(CACHE_DIR, '.geo_cache.json') if CACHE_DIR else None

TTL = 7 * 24 * 3600      # re-lookup a resolved IP after about a week
TTL_JITTER = 0.3         # +/-30%, so a batch resolved together doesn't expire together
NEGATIVE_TTL = 6 * 3600  # ip-api answered "fail" (reserved/bogon address)
ERROR_TTL = 5 * 60       # the request itself failed; retry soon, but don't spin
BATCH_SIZE = 100         # ip-api's per-request maximum
BUDGET = 20              # seconds we are willing to spend inside one page request
ENDPOINT = ('http://ip-api.com/batch'
            '?fields=status,message,query,country,countryCode,lat,lon,as,asname,isp')

_lock = threading.RLock()
_cache = {}              # ip -> {'at': ts, 'geo': {...} or None, 'err': bool}
_cache_mtime = None
_loaded = False


# --------------------------------------------------------------------------
# cache (memory first, disk as a warm start shared between workers)
# --------------------------------------------------------------------------

def _load():
    """Merge in the on-disk cache if another worker has written a newer one."""
    global _cache, _cache_mtime, _loaded
    if not CACHE_FILE:
        _loaded = True
        return _cache
    try:
        mtime = os.stat(CACHE_FILE).st_mtime
    except OSError:
        mtime = None
    if _loaded and mtime == _cache_mtime:
        return _cache
    if mtime is not None:
        try:
            with open(CACHE_FILE) as f:
                disk = json.load(f)
            if isinstance(disk, dict):
                # Keep whichever copy of each entry is newer.
                for ip, entry in disk.items():
                    cur = _cache.get(ip)
                    if not cur or entry.get('at', 0) > cur.get('at', 0):
                        _cache[ip] = entry
        except Exception:
            pass
    _cache_mtime = mtime
    _loaded = True
    return _cache


def _save():
    global _cache_mtime
    if not CACHE_FILE:
        return
    try:
        tmp = '{}.{}.tmp'.format(CACHE_FILE, os.getpid())
        with open(tmp, 'w') as f:
            json.dump(_cache, f)
        os.replace(tmp, CACHE_FILE)
        _cache_mtime = os.stat(CACHE_FILE).st_mtime
    except Exception as e:
        print("geoip: cache not persisted ({}); lookups still work".format(e),
              file=sys.stderr)


# --------------------------------------------------------------------------
# freshness
# --------------------------------------------------------------------------

def _usable(ip):
    return bool(ip) and ip not in ('0.0.0.0', '127.0.0.1', '::')


def _ttl_for(ip, entry):
    if entry.get('err'):
        return ERROR_TTL
    if entry.get('geo') is None:
        return NEGATIVE_TTL
    # Spread re-lookups out so a set resolved in one pass doesn't all expire at
    # the same moment a week later. Deterministic per IP, so it stays stable.
    frac = (zlib.crc32(ip.encode()) % 1000) / 1000.0
    return TTL * (1 - TTL_JITTER + 2 * TTL_JITTER * frac)


def _fresh(ip, entry, now):
    return bool(entry) and now - entry.get('at', 0) < _ttl_for(ip, entry)


# --------------------------------------------------------------------------
# ip-api
# --------------------------------------------------------------------------

def _fetch_batch(batch):
    """Returns (results, requests_left, seconds_until_reset)."""
    r = requests.post(ENDPOINT, json=batch, timeout=15)
    if r.status_code == 429:
        raise RuntimeError('rate limited by ip-api (HTTP 429)')
    r.raise_for_status()
    def _hdr(name):
        try:
            return int(r.headers.get(name))
        except (TypeError, ValueError):
            return None
    results = r.json()
    return (results if isinstance(results, list) else []), _hdr('X-Rl'), _hdr('X-Ttl')


def _record(entries, now, err=False):
    with _lock:
        for res in entries:
            if err:
                ip = res
                if ip:
                    _cache[ip] = {'at': now, 'geo': None, 'err': True}
                continue
            ip = (res or {}).get('query')
            if not ip:
                continue
            geo = None
            if res.get('status') == 'success':
                geo = {k: res.get(k) for k in
                       ('country', 'countryCode', 'lat', 'lon', 'as', 'asname', 'isp')}
            _cache[ip] = {'at': now, 'geo': geo}


# --------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------

def geolocate(ips, budget=BUDGET):
    """Resolve `ips`, blocking for at most `budget` seconds.

    Returns (geo, info) where geo is {ip: geo-dict-or-None} for everything
    known, and info describes what happened so the page can say so.
    """
    now = time.time()
    with _lock:
        cache = _load()
        unique = [ip for ip in dict.fromkeys(ips) if _usable(ip)]
        stale = [ip for ip in unique if not _fresh(ip, cache.get(ip), now)]

    info = {'requested': len(unique), 'stale': len(stale), 'resolved': 0,
            'remaining': len(stale), 'error': None, 'rate_limited': False,
            'took': 0.0}
    started = time.time()
    deadline = started + budget

    for i in range(0, len(stale), BATCH_SIZE):
        if time.time() >= deadline:
            break
        batch = stale[i:i + BATCH_SIZE]
        try:
            results, left, ttl = _fetch_batch(batch)
        except Exception as e:
            info['error'] = str(e)
            info['rate_limited'] = '429' in str(e) or 'rate limited' in str(e).lower()
            # Back these off briefly so a hard failure doesn't retry every reload.
            _record(batch, time.time(), err=True)
            print("geoip: batch failed: {}".format(e), file=sys.stderr)
            break
        _record(results, time.time())
        info['resolved'] += len(results)
        info['remaining'] = len(stale) - (i + len(batch))
        if left is not None and left <= 0:
            # Quota exhausted for this window; the rest waits for a later request.
            info['rate_limited'] = True
            break

    if info['resolved']:
        with _lock:
            _save()

    info['took'] = round(time.time() - started, 2)
    if stale:
        print("geoip: resolved {} of {} in {}s ({} left{})".format(
            info['resolved'], len(stale), info['took'], info['remaining'],
            ', rate limited' if info['rate_limited'] else ''), file=sys.stderr)

    with _lock:
        out = {}
        for ip in unique:
            entry = _cache.get(ip)
            if entry and not entry.get('err'):
                out[ip] = entry.get('geo')
        return out, info
