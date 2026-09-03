#!/usr/bin/env python3
"""IP geolocation for the master node distribution page.

Lookups go through ip-api.com's free batch endpoint (no API key, HTTP only,
rate limited to ~15 requests/minute with up to 100 IPs per request).  A node's
location almost never changes, so results are cached on disk for a week and
refreshed by a background thread: page requests only ever read the cache and
never block on the network.
"""

import json
import os
import sys
import threading
import time

import requests

CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.geo_cache.json')

TTL = 7 * 24 * 3600     # re-lookup an IP at most once a week
NEGATIVE_TTL = 6 * 3600  # retry failed lookups sooner
BATCH_SIZE = 100         # ip-api's per-request maximum
BATCH_DELAY = 5          # seconds between batches (~12 req/min, under the limit)
ENDPOINT = 'http://ip-api.com/batch?fields=status,message,query,country,countryCode,lat,lon,as,asname,isp'

_lock = threading.Lock()
_cache = None            # ip -> {'at': ts, 'geo': {...} or None}
_worker = None
_state = {'running': False, 'pending': 0, 'updated': 0, 'last_run': 0, 'error': None}


def _load_locked():
    global _cache
    if _cache is None:
        try:
            with open(CACHE_FILE) as f:
                loaded = json.load(f)
            _cache = loaded if isinstance(loaded, dict) else {}
        except Exception:
            _cache = {}
    return _cache


def _save_locked():
    try:
        tmp = CACHE_FILE + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(_cache, f)
        os.replace(tmp, CACHE_FILE)
    except Exception as e:
        print("geoip: failed to write cache: {}".format(e), file=sys.stderr)


def _usable(ip):
    return bool(ip) and ip not in ('0.0.0.0', '127.0.0.1', '::')


def _fresh(entry, now):
    if not entry:
        return False
    ttl = TTL if entry.get('geo') else NEGATIVE_TTL
    return now - entry.get('at', 0) < ttl


def lookup(ips):
    """Returns {ip: geo-or-None} for every requested IP already in the cache.

    Never touches the network — IPs that have not been resolved yet are simply
    absent from the returned dict.
    """
    now = time.time()
    with _lock:
        cache = _load_locked()
        out = {}
        for ip in ips:
            if not _usable(ip):
                continue
            entry = cache.get(ip)
            if entry is not None:
                out[ip] = entry.get('geo')
        return out


def _stale_locked(ips, now):
    cache = _load_locked()
    return [ip for ip in dict.fromkeys(ips)
            if _usable(ip) and not _fresh(cache.get(ip), now)]


def _fetch_batch(batch):
    r = requests.post(ENDPOINT, json=batch, timeout=20)
    r.raise_for_status()
    results = r.json()
    return results if isinstance(results, list) else []


def _run(pending):
    updated = 0
    failed = True   # cleared as soon as any batch comes back
    try:
        for i in range(0, len(pending), BATCH_SIZE):
            batch = pending[i:i + BATCH_SIZE]
            try:
                results = _fetch_batch(batch)
            except Exception as e:
                with _lock:
                    _state['error'] = str(e)
                print("geoip: batch failed: {}".format(e), file=sys.stderr)
                time.sleep(BATCH_DELAY)
                continue
            failed = False

            now = time.time()
            with _lock:
                cache = _load_locked()
                for res in results:
                    ip = (res or {}).get('query')
                    if not ip:
                        continue
                    geo = None
                    if res.get('status') == 'success':
                        geo = {k: res.get(k) for k in
                               ('country', 'countryCode', 'lat', 'lon', 'as', 'asname', 'isp')}
                    cache[ip] = {'at': now, 'geo': geo}
                    updated += 1
                _state['updated'] = updated
                _state['pending'] = max(0, len(pending) - (i + len(batch)))
                _save_locked()

            if i + BATCH_SIZE < len(pending):
                time.sleep(BATCH_DELAY)
        if not failed:
            with _lock:
                _state['error'] = None
    finally:
        with _lock:
            _state['running'] = False
            _state['pending'] = 0
            _state['last_run'] = time.time()
        print("geoip: resolved {} of {} addresses".format(updated, len(pending)), file=sys.stderr)


def refresh(ips):
    """Kick off a background lookup for any IP that is missing or stale.

    Returns the number of addresses queued (0 if everything is fresh or a
    refresh is already in flight).
    """
    global _worker
    now = time.time()
    with _lock:
        if _state['running']:
            return _state['pending']
        pending = _stale_locked(ips, now)
        if not pending:
            return 0
        _state['running'] = True
        _state['pending'] = len(pending)
        _state['updated'] = 0
        _worker = threading.Thread(target=_run, args=(pending,), daemon=True,
                                   name='geoip-refresh')
        _worker.start()
        return len(pending)


def status():
    with _lock:
        return dict(_state)
