#!/usr/bin/env python3

import flask
from datetime import datetime, timedelta, timezone
import babel.dates
import json
import sys
import statistics
import string
import requests
import time
from base64 import b32encode, b16decode
from werkzeug.routing import BaseConverter
from pygments import highlight
from pygments.lexers import JsonLexer
from pygments.formatters import HtmlFormatter
import subprocess
import qrcode
from io import BytesIO
from jinja2 import Environment

import config
import local_config
import geoip
from lmq import FutureJSON, lmq_connection

import base64
import nacl.encoding
import nacl.hash 
import pysodium
import sha3
import base58

# Make a dict of config.* to pass to templating
conf = {x: getattr(config, x) for x in dir(config) if not x.startswith('__')}

git_rev = subprocess.run(["git", "rev-parse", "--short=9", "HEAD"], stdout=subprocess.PIPE, text=True)
if git_rev.returncode == 0:
    git_rev = git_rev.stdout.strip()
else:
    git_rev = "(unknown)"

app = flask.Flask(__name__)


# env = Environment(extensions=["jinja2.ext.i18n"])
# jinja_env = Environment('])
app.jinja_options['extensions'] = ['jinja2.ext.loopcontrols']


class Hex64Converter(BaseConverter):
    def __init__(self, url_map):
        super().__init__(url_map)
        self.regex = "[0-9a-fA-F]{64}"

app.url_map.converters['hex64'] = Hex64Converter


@app.template_filter('format_datetime')
def format_datetime(value, format='long'):
    # Explicit locale: Babel otherwise falls back to LC_TIME, which on macOS is
    # often set to a bare charset (e.g. "UTF-8") that Locale.parse rejects.
    return babel.dates.format_datetime(value, format, tzinfo=babel.dates.get_timezone('UTC'), locale='en')

@app.template_filter('from_timestamp')
def from_timestamp(value):
    return datetime.fromtimestamp(value, tz=timezone.utc)

@app.template_filter('ago')
def datetime_ago(value):
    delta = datetime.now(timezone.utc) - value
    disp=''
    if delta.days < 0:
        delta = -delta
        disp += '-'
    if delta.days > 0:
        disp += '{}d '.format(delta.days)
    disp += '{:d}:{:02d}:{:02d}'.format(delta.seconds // 3600, delta.seconds // 60 % 60, delta.seconds % 60)
    return disp


@app.template_filter('reltime')
def relative_time(seconds, two_part=False, in_ago=True, neg_is_now=False):
    if isinstance(seconds, timedelta):
        seconds = seconds.seconds + 86400*seconds.days

    ago = False
    if seconds == 0 or (neg_is_now and seconds < 0):
        return 'now'
    elif seconds < 0:
        seconds = -seconds
        ago = True

    if two_part:
        if seconds < 3600:
            delta = '{:.0f} minutes {:.0f} seconds'.format(seconds//60, seconds%60//1)
        elif seconds < 24 * 3600:
            delta = '{:.0f} hours {:.1f} minutes'.format(seconds//3600, seconds%3600/60)
        elif seconds < 10 * 86400:
            delta = '{:.0f} days {:.1f} hours'.format(seconds//86400, seconds%86400/3600)
        else:
            delta = '{:.1f} days'.format(seconds / 86400)
    elif seconds < 90:
        delta = '{:.0f} seconds'.format(seconds)
    elif seconds < 90 * 60:
        delta = '{:.1f} minutes'.format(seconds / 60)
    elif seconds < 36 * 3600:
        delta = '{:.1f} hours'.format(seconds / 3600)
    elif seconds < 99.5 * 86400:
        delta = '{:.1f} days'.format(seconds / 86400)
    else:
        delta = '{:.0f} days'.format(seconds / 86400)

    return delta if not in_ago else delta + ' ago' if ago else 'in ' + delta


@app.template_filter('roundish')
def filter_round(value):
    return ("{:.0f}" if value >= 100 or isinstance(value, int) else "{:.1f}" if value >= 10 else "{:.2f}").format(value)

@app.template_filter('chop0')
def filter_chop0(value):
    value = str(value)
    if '.' in value:
        return value.rstrip('0').rstrip('.')
    return value

si_suffix = ['', 'k', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y']
@app.template_filter('si')
def format_si(value):
    i = 0
    while value >= 1000 and i < len(si_suffix) - 1:
        value /= 1000
        i += 1
    return filter_round(value) + '{}'.format(si_suffix[i])

@app.template_filter('beldex')
def format_beldex(atomic, tag=True, fixed=False, decimals=9, zero=None):
    """Formats an atomic current value as a human currency value.
    tag - if False then don't append " BDX"
    fixed - if True then don't strip insignificant trailing 0's and '.'
    decimals - at how many decimal we should round; the default is full precision
    fixed - if specified, replace 0 with this string
    """
    if atomic == 0 and zero:
        disp = zero
    else:
        disp = "{{:.{}f}}".format(decimals).format(atomic * 1e-9)
        if not fixed and decimals > 0:
            disp = disp.rstrip('0').rstrip('.')
    if tag:
        disp += ' BDX'
    return disp

# For some inexplicable reason some hex fields are provided as array of byte integer values rather
# than hex.  This converts such a monstrosity to hex.
@app.template_filter('flag')
def country_flag(code):
    """Regional-indicator flag emoji for a 2-letter ISO country code."""
    if not code or len(code) != 2 or not code.isalpha():
        return '\N{WAVING WHITE FLAG}'
    return ''.join(chr(0x1F1E6 + ord(c) - ord('A')) for c in code.upper())


@app.template_filter('bytes_to_hex')
def bytes_to_hex(b):
    return "".join("{:02x}".format(x) for x in b)

@app.template_filter('base32z')
def base32z(hex):
    return b32encode(b16decode(hex, casefold=True)).translate(
            bytes.maketrans(
                b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
                b'ybndrfg8ejkmcpqxot1uwisza345h769')).decode().rstrip('=')


@app.template_filter('ellipsize')
def ellipsize(string, leading=10, trailing=5, ellipsis='...'):
    if len(string) <= leading + trailing + 3:
        return string
    return string[0:leading] + ellipsis + ('' if not trailing else string[-trailing:])


@app.after_request
def add_global_headers(response):
    for k, v in {
            'Cache-Control': 'no-store',
            'Access-Control-Allow-Origin': '*',
            }.items():
        if k not in response.headers:
            response.headers[k] = v
    return response

@app.errorhandler(500)
def internal_error(e):
    print("daemon-busy page served for {} via 500 handler (see traceback above)".format(
            flask.request.path), file=sys.stderr)
    # In this app an unhandled exception almost always traces back to a beldexd
    # RPC timeout while the daemon is busy/syncing (futures return None and
    # downstream code trips over it). Render a friendly auto-retrying page;
    # the real traceback is still printed to the log.
    return flask.render_template('daemon_unavailable.html', info=None), 503


@app.route('/style.css')
def css():
    return flask.send_from_directory('static', 'style.css')


# Centralized get_info with a stale fallback: every route goes through
# _CachedInfoFuture, so a momentarily-unresponsive daemon serves slightly
# stale pages instead of crashing or showing the busy page. The last good
# snapshot also persists to disk so Flask restarts keep it.
import os as _os_info
_INFO_DISK_CACHE = _os_info.path.join(_os_info.path.dirname(_os_info.path.abspath(__file__)),
        '.info_cache.json')
_last_info = {'data': None, 'ts': 0}
_LAST_INFO_MAX_AGE = 3600  # seconds

def _info_cache_load():
    if _last_info['data'] is None:
        try:
            with open(_INFO_DISK_CACHE) as f:
                saved = json.load(f)
            _last_info['data'] = saved['data']
            _last_info['ts'] = saved['ts']
        except Exception:
            _last_info['ts'] = -1  # tried; nothing usable

def _info_cache_store(info):
    _last_info['data'] = dict(info)
    _last_info['ts'] = time.time()
    try:
        with open(_INFO_DISK_CACHE, 'w') as f:
            json.dump({'data': _last_info['data'], 'ts': _last_info['ts']}, f)
    except Exception:
        pass

class _CachedInfoFuture:
    """Drop-in replacement for the get_info FutureJSON: .get() returns fresh
    info when the daemon answers, else the last snapshot (up to 1h old) with
    .stale set, else None."""
    def __init__(self, lmq, beldexd):
        self._fut = FutureJSON(lmq, beldexd, 'rpc.get_info', 1)
        # self._fut = _CachedInfoFuture(lmq, beldexd)
        self.stale = False

    def get(self):
        info = self._fut.get()
        if info:
            # Only store a pristine copy (routes mutate the returned dict)
            if _last_info['data'] is None or time.time() - _last_info['ts'] > 5:
                _info_cache_store(info)
            return info
        _info_cache_load()
        if _last_info['data'] and time.time() - _last_info['ts'] < _LAST_INFO_MAX_AGE:
            self.stale = True
            return dict(_last_info['data'])
        return None


def get_info_or_stale(inforeq):
    """Returns (info, stale) from a _CachedInfoFuture."""
    info = inforeq.get()
    return info, (info is not None and getattr(inforeq, 'stale', False))


def get_mns_future(lmq, beldexd):
    return FutureJSON(lmq, beldexd, 'rpc.get_master_nodes', 5,
            args={
                'all': False,
                'fields': { x: True for x in ('master_node_pubkey', 'requested_unlock_height', 'last_reward_block_height',
                    'last_reward_transaction_index', 'active', 'funded', 'earned_downtime_blocks',
                    'master_node_version', 'contributors', 'total_contributed', 'total_reserved',
                    'staking_requirement', 'portions_for_operator', 'operator_address', 'pubkey_ed25519',
                    'last_uptime_proof', 'state_height', 'swarm_id', 'public_ip') } })

def get_mns(mns_future, info_future):
    info = info_future.get()
    awaiting_mns, active_mns, inactive_mns = [], [], []
    mn_states = mns_future.get()
    mn_states = mn_states['master_node_states'] if mn_states and 'master_node_states' in mn_states else []
    for mn in mn_states:
        mn['staking_requirement'] = int(mn['staking_requirement'])
        mn['total_reserved'] = int(mn.get('total_reserved', 0))
        mn['total_contributed'] = int(mn.get('total_contributed', 0))
        mn['contribution_open'] = mn['staking_requirement'] - mn['total_reserved']
        mn['contribution_required'] = mn['staking_requirement'] - mn['total_contributed']
        mn['num_contributions'] = sum(len(x['locked_contributions']) for x in mn['contributors'] if 'locked_contributions' in x)

        if mn['active']:
            active_mns.append(mn)
        elif mn['funded']:
            mn['decomm_blocks_remaining'] = max(mn['earned_downtime_blocks'], 0)
            mn['decomm_blocks'] = info['height'] - mn['state_height']
            inactive_mns.append(mn)
        else:
            awaiting_mns.append(mn)
    return awaiting_mns, active_mns, inactive_mns


def get_quorums_future(lmq, beldexd, height):
    return FutureJSON(lmq, beldexd, 'rpc.get_quorum_state', 30,
            args={ 'start_height': height-55, 'end_height': height })


def get_quorums(quorums_future):
    qkey = ["obligation", "checkpoint", "flash", "POS"]
    quo = {x: [] for x in qkey}

    quorums = quorums_future.get()
    quorums = quorums['quorums'] if 'quorums' in quorums else []
    for q in quorums:
        if q['quorum_type'] <= len(qkey):
            quo[qkey[q['quorum_type']]].append(q)
        else:
            print("Something getting wrong in quorums: found unknown quorum_type={}".format(q['quorum_type']), file=sys.stderr)
    return quo

def get_mempool_future(lmq, beldexd):
    return FutureJSON(lmq, beldexd, 'rpc.get_transaction_pool', 5, args={"tx_extra":True," tx_extra_raw": True, "stake_info":True})

def parse_mempool(mempool_future):
    # mempool RPC return values are about as nasty as can be.  For each mempool tx, we get back
    # *both* binary+hex encoded values and JSON-encoded values slammed into a string, which means we
    # have to invoke an *extra* JSON parser for each tx.  This is terrible.
    mp = mempool_future.get()
    if mp is None:  # RPC failed/timed out
        return None
    if 'transactions' in mp:
        rename = {
                'id_hash': 'tx_hash',
                'blob_size': 'size',
                'max_used_block_id_hash': 'max_used_block',
                'max_used_block_height': 'max_used_height',
                'last_failed_id_hash': 'last_failed_hash',
                'receive_time': 'received_timestamp',
                'tx_blob': 'data',
        }
        for tx in mp['transactions']:
            info = json.loads(tx["tx_json"])
            info['tx_extra_raw'] = bytes_to_hex(info['extra'])
            del info['extra']
            tx.update(info)

            for from_k, to_k in rename.items():
                tx[to_k] = tx.pop(from_k)

        mp['txs'] = mp.pop('transactions')

    if 'txs' in mp:
        # If we have a cached value we have already sorted it
        if '_sorted' not in mp:
            mp['txs'].sort(key=lambda tx: (tx['received_timestamp'], tx['tx_hash']))
            mp['_sorted'] = True
        else:
            mp['txs'] = []
        return mp


@app.context_processor
def template_globals():
    now = datetime.now(timezone.utc)
    return {
        'config': conf,
        'server': {
            'datetime': now,
            'timestamp': now.timestamp(),
            'revision': git_rev,
        },
    }


@app.route('/page/<int:page>')
@app.route('/page/<int:page>/<int:per_page>')
@app.route('/range/<int:first>/<int:last>')
@app.route('/autorefresh/<int:refresh>')
@app.route('/')
def main(refresh=None, page=0, per_page=None, first=None, last=None):
    lmq, beldexd = lmq_connection()
    inforeq = _CachedInfoFuture(lmq, beldexd)
    stake = FutureJSON(lmq, beldexd, 'rpc.get_staking_requirement', 10)
    base_fee = FutureJSON(lmq, beldexd, 'rpc.get_fee_estimate', 10)
    hfinfo = FutureJSON(lmq, beldexd, 'rpc.hard_fork_info', 10)
    mempool = get_mempool_future(lmq, beldexd)
    # Master node lists moved to /master_nodes; the home page only shows counts,
    # so request just two booleans per node instead of the full states.
    mn_counts_req = FutureJSON(lmq, beldexd, 'rpc.get_master_nodes', 15, cache_key='counts',
            args={'all': False, 'fields': {'active': True, 'funded': True}})
    checkpoints = FutureJSON(lmq, beldexd, 'rpc.get_checkpoints', args={"count": 3})

    # This call is slow the first time it gets called in beldexd but will be fast after that, so call
    # it with a very short timeout.  It's also an admin-only command, so will always fail if we're
    # using a restricted RPC interface.
    coinbase = FutureJSON(lmq, beldexd, 'admin.get_coinbase_tx_sum', 10, timeout=1, fail_okay=True,
            args={"height":0, "count":2**31-1})

    custom_per_page = ''
    if per_page is None or per_page <= 0 or per_page > config.max_blocks_per_page:
        per_page = config.blocks_per_page
    else:
        custom_per_page = '/{}'.format(per_page)

    # We have some chained request dependencies here and below, so get() them as needed; all other
    # non-dependent requests should already have a future initiated above so that they can
    # potentially run in parallel.
    info, stale_info = get_info_or_stale(inforeq)
    if info is None:
        # get_info timed out and we have no recent cached copy: daemon is
        # unreachable. Render a friendly auto-retrying page instead of crashing.
        print("daemon-busy page served for {}: get_info timed out".format(flask.request.path),
                file=sys.stderr)
        return flask.render_template('daemon_unavailable.html', info=None), 503
    if stale_info:
        print("serving {} with cached get_info (daemon busy)".format(flask.request.path),
                file=sys.stderr)
    height = info['height']
    info['testnet']  = info['nettype'] == 'testnet'
    info['devnet']   = info['nettype'] == 'devnet'
    bns = info.get('bns_counts', 0)
    # Permalinked block range:
    if first is not None and last is not None and 0 <= first <= last and last <= first + 99:
        start_height, end_height = first, last
        if end_height - start_height + 1 != per_page:
            per_page = end_height - start_height + 1;
            custom_per_page = '/{}'.format(per_page)
        if start_height > height:
            flask.abort(404)
        # We generally can't get a perfect page number because our range (e.g. 5-14) won't line up
        # with pages (e.g. 10-19, 0-19), so just get as close as we can.  Next/Prev page won't be
        # quite right, but they'll be within half a page.
        page = round((height - 1 - end_height) / per_page)
    else:
        end_height = max(0, height - per_page*page - 1)
        start_height = max(0, end_height - per_page + 1)

    blocks = (FutureJSON(lmq, beldexd, 'rpc.get_block_headers_range', cache_key='main', args={
        'start_height': start_height,
        'end_height': end_height,
        'get_tx_hashes': True,
        }).get() or {}).get('headers', [])

    # If 'txs' is already there then it is probably left over from our cached previous call through
    # here.
    if blocks and 'txs' not in blocks[0]:
        txids = []
        for b in blocks:
            b['txs'] = []
            if 'miner_tx_hash' in b and b['miner_tx_hash']:
                txids.append(b['miner_tx_hash'])
            if 'tx_hashes' in b:
                txids += b['tx_hashes']
        if txids:
            txs = parse_txs(tx_req(lmq, beldexd, txids, cache_key='recent').get())
            i = 0
            for tx in txs:
                # TXs should come back in the same order so we can just skip ahead one when the block
                # height changes rather than needing to search for the block
                if 'vin' in tx and len(tx['vin']) == 1 and 'gen' in tx['vin'][0]:

                    tx['coinbase'] = True
                if blocks[i]['height'] != tx['block_height']:
                    i += 1
                    while i < len(blocks) and blocks[i]['height'] != tx['block_height']:
                        print("Something getting wrong: missing txes?", file=sys.stderr)
                        i += 1
                    if i >= len(blocks):
                        print("Something getting wrong: have leftover txes")
                        break
                blocks[i]['txs'].append(tx)

    # Lightweight master node counts for the stat tiles
    mn_counts = {'active': 0, 'awaiting': 0, 'decommissioned': 0}
    for mn in (mn_counts_req.get() or {}).get('master_node_states', []):
        if mn.get('active'):
            mn_counts['active'] += 1
        elif mn.get('funded'):
            mn_counts['decommissioned'] += 1
        else:
            mn_counts['awaiting'] += 1

    supply = fetch_circulating_supply()
    circulating_supply = supply * 1_000_000_000 if supply is not None else None

    # Fall back to safe defaults for any RPC that failed/timed out so a busy
    # daemon degrades the page instead of 500ing it.
    return flask.render_template('index.html',
            bns=bns,
            info=info,
            stake=stake.get() or {'staking_requirement': 0},
            fees=base_fee.get() or {'fee_per_byte': 0, 'fee_per_output': 0,
                'flash_fee_per_byte': 0, 'flash_fee_per_output': 0, 'flash_fee_fixed': 0},
            emission=coinbase.get(),
            circulating_supply=circulating_supply,
            hf=hfinfo.get() or {'version': 0},
            mn_counts=mn_counts,
            blocks=blocks,
            block_size_median=statistics.median(b['block_size'] for b in blocks) if blocks else 0,
            page=page,
            per_page=per_page,
            custom_per_page=custom_per_page,
            mempool=parse_mempool(mempool) or {'txs': []},
            checkpoints=checkpoints.get(),
            refresh=refresh,
            stale_info=stale_info,
            )


@app.route('/txpool')
def mempool():
    lmq, beldexd = lmq_connection()
    info = _CachedInfoFuture(lmq, beldexd)
    mempool = get_mempool_future(lmq, beldexd)

    return flask.render_template('mempool.html',
            info=info.get(),
            mempool=parse_mempool(mempool),
            )

@app.route('/master_nodes')
def mns():
    lmq, beldexd = lmq_connection()
    info = _CachedInfoFuture(lmq, beldexd)
    awaiting, active, inactive = get_mns(get_mns_future(lmq, beldexd), info)

    return flask.render_template('master_nodes.html',
        info=info.get(),
        active_mns=active,
        awaiting_mns=awaiting,
        inactive_mns=inactive,
        )

def _mn_status(mn):
    if mn.get('active'):
        return 'active'
    if mn.get('funded'):
        return 'decommissioned'
    return 'awaiting'


def _distribution(mns):
    """Aggregates master nodes by country, ASN and map point using whatever
    geolocation data is already cached (see geoip.py)."""
    ips = [mn.get('public_ip') for mn in mns if mn.get('public_ip')]
    geo = geoip.lookup(ips)

    by_country, by_asn, points = {}, {}, {}
    located = 0
    for mn in mns:
        g = geo.get(mn.get('public_ip'))
        if not g:
            continue
        located += 1
        status = _mn_status(mn)

        cc = g.get('countryCode') or 'XX'
        country = g.get('country') or 'Unknown'
        c = by_country.setdefault(cc, {'country': country, 'code': cc, 'count': 0})
        c['count'] += 1

        asn_key = g.get('as') or g.get('asname') or 'Unknown'
        a = by_asn.setdefault(asn_key, {
            'asn': g.get('as'),
            'name': g.get('asname') or g.get('isp') or g.get('as') or 'Unknown',
            'count': 0})
        a['count'] += 1

        lat, lon = g.get('lat'), g.get('lon')
        if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
            key = '{:.1f},{:.1f}'.format(lat, lon)
            p = points.setdefault(key, {'lat': lat, 'lon': lon, 'country': country,
                'count': 0, 'active': 0, 'decommissioned': 0, 'awaiting': 0})
            p['count'] += 1
            p[status] += 1

    by_count = lambda d: sorted(d.values(), key=lambda x: (-x['count'], x.get('name') or x.get('country')))
    return {
        'total': len(mns),
        'with_ip': len(ips),
        'located': located,
        'unresolved': len(mns) - located,
        'countries': len(by_country),
        'providers': len(by_asn),
        'by_country': by_count(by_country),
        'by_asn': by_count(by_asn),
        'points': sorted(points.values(), key=lambda p: -p['count']),
    }


@app.route('/distribution')
def distribution():
    lmq, beldexd = lmq_connection()
    inforeq = _CachedInfoFuture(lmq, beldexd)
    mns_future = get_mns_future(lmq, beldexd)

    info, stale_info = get_info_or_stale(inforeq)
    if info is None:
        print("daemon-busy page served for /distribution: get_info timed out", file=sys.stderr)
        return flask.render_template('daemon_unavailable.html', info=None), 503
    info['testnet'] = info['nettype'] == 'testnet'
    info['devnet'] = info['nettype'] == 'devnet'

    awaiting, active, inactive = get_mns(mns_future, inforeq)
    mns = active + inactive + awaiting

    # Queue any missing/stale lookups in the background, then build the page
    # from whatever is cached right now. The first ever load therefore renders
    # immediately (mostly empty) and fills in over the next refreshes.
    ips = [mn['public_ip'] for mn in mns if mn.get('public_ip')]
    try:
        geoip.refresh(ips)
    except Exception as e:
        print("geoip refresh failed: {}".format(e), file=sys.stderr)
    geo_status = geoip.status()

    dist = _distribution(mns)
    dist['status_counts'] = {
        'active': len(active),
        'decommissioned': len(inactive),
        'awaiting': len(awaiting),
    }

    return flask.render_template('distribution.html',
            info=info,
            stale_info=stale_info,
            dist=dist,
            geo_status=geo_status,
            # Refresh while lookups are still in flight so the map fills in.
            refresh=20 if (geo_status.get('running') or dist['located'] == 0) else None,
            )


def tx_req(lmq, beldexd, txids, cache_key='single', **kwargs):
    return FutureJSON(lmq, beldexd, 'rpc.get_transactions', cache_seconds=10, cache_key=cache_key,
            args={
                "txs_hashes": txids,
                "decode_as_json": True,
                "tx_extra": True,
                "tx_extra_raw": True,
                "prune": True,
                "stake_info": True,
                },
            **kwargs)

def tx_req_prune(lmq, beldexd, txids, cache_key='single', **kwargs):
    return FutureJSON(lmq, beldexd, 'rpc.get_transactions', cache_seconds=10, cache_key=cache_key,
            args={
                "txs_hashes": txids,
                "decode_as_json": True,
                "tx_extra": True,
                "tx_extra_raw": True,
                "prune": False,
                "stake_info": True,
                },
            **kwargs)

def mn_req(lmq, beldexd, pubkey, **kwargs):
    return FutureJSON(lmq, beldexd, 'rpc.get_master_nodes', 5, cache_key='single',
            args={"master_node_pubkeys": [pubkey]}, **kwargs
        )


def block_header_req(lmq, beldexd, hash_or_height, **kwargs):
    if isinstance(hash_or_height, int) or (len(hash_or_height) <= 10 and hash_or_height.isdigit()):
        return FutureJSON(lmq, beldexd, 'rpc.get_block_header_by_height', cache_key='single',
                args={ "height": int(hash_or_height) }, **kwargs)
    else:
        return FutureJSON(lmq, beldexd, 'rpc.get_block_header_by_hash', cache_key='single',
                args={ 'hash': hash_or_height }, **kwargs)


def block_with_txs_req(lmq, beldexd, hash_or_height, **kwargs):
    args = { 'get_tx_hashes': True }
    if isinstance(hash_or_height, int) or (len(hash_or_height) <= 10 and hash_or_height.isdigit()):
        args['height'] = int(hash_or_height)
    else:
        args['hash'] = hash_or_height

    return FutureJSON(lmq, beldexd, 'rpc.get_block', cache_key='single', args=args, **kwargs)


def bns_decrypt(lmq, beldexd, name, bns_type, encrypted_value, **kwargs):
    return FutureJSON(lmq, beldexd, 'rpc.bns_value_decrypt', args={
        "name": name,
        "type": bns_type,
        "encrypted_value": encrypted_value,
    })


def bns_info(lmq, beldexd, name, **kwargs):
    # Generate the hash using blake2b
    name_hash = nacl.hash.blake2b(name.encode(), encoder=nacl.encoding.RawEncoder)
    # Convert to Base64
    name_hash_b64 = base64.b64encode(name_hash).decode('ascii')
    
    print(f"Name: {name}, Name Hash (Base64): {name_hash_b64}")
    
    # Send name_hash as an array
    fut = FutureJSON(lmq, beldexd, 'rpc.bns_names_to_owners', args={
        "name_hash": [name_hash_b64]  # Send as an array
    })
    
    # Wait for result
    result = fut.get()
    if result is None:
        print("Error: No result returned from FutureJSON.")
        return None
        
    return result

@app.route('/bns/<string:name>')
@app.route('/bns/<string:name>/<int:more_details>')
def show_bns(name, more_details=False):
    name = name.lower()
    lmq, beldexd = lmq_connection()
    info = _CachedInfoFuture(lmq, beldexd)

    # Validation
    if len(name) > 64 or not all(c.isalnum() or c in '_-' for c in name):
        return flask.render_template('not_found.html',
            info=info.get(),
            type='bad_search',
            id=name,
            )
    if name in ["localhost", "mnode", "beldex"]:
        return flask.render_template('not_found.html',
            info=info.get(),
            type='bns_reserved',
            id=name,
        )

    # Lookup
    bns_data = {'name': name}
    query_name = name + '.bdx'

    bnsinfo = bns_info(lmq, beldexd, query_name)
    if not bnsinfo or 'result' not in bnsinfo:
        bns_data['result'] = True  # no result
    else:
        bns_entry = bnsinfo['result'][0]
        bns_data['result'] = bns_entry

        # Decrypt values if present
        for bns_type, field in [
            ('bchat', 'encrypted_bchat_value'),
            ('belnet', 'encrypted_belnet_value'),
            ('wallet', 'encrypted_wallet_value'),
            ('eth_addr', 'encrypted_eth_addr_value'),
        ]:
            enc_val = bns_entry.get(field, "")
            if enc_val:
                dec = bns_decrypt(lmq, beldexd, query_name, bns_type, enc_val).get()
                if 'value' in dec:
                    bns_data['result'][f"{bns_type}_value"] = dec['value']

    # More details (syntax highlighting)
    if more_details:
        formatter = HtmlFormatter(cssclass="syntax-highlight", style="paraiso-dark")
        more_details = {
            'details_css': formatter.get_style_defs('.syntax-highlight'),
            'details_html': highlight(json.dumps(bns_data, indent=2), JsonLexer(), formatter),
        }
    else:
        more_details = {}
                
    return flask.render_template('bns.html',
            info=info.get(),
            bns=bns_data,
            **more_details,
            )

@app.route('/master_node/<hex64:pubkey>')  # For backwards compatibility with old explorer URLs
@app.route('/mn/<hex64:pubkey>')
@app.route('/mn/<hex64:pubkey>/<int:more_details>')
def show_mn(pubkey, more_details=False):
    lmq, beldexd = lmq_connection()
    info = _CachedInfoFuture(lmq, beldexd)
    hfinfo = FutureJSON(lmq, beldexd, 'rpc.hard_fork_info', 10)
    mn = mn_req(lmq, beldexd, pubkey).get()
    quos = get_quorums_future(lmq, beldexd, info.get()['height'])


    if 'master_node_states' not in mn or not mn['master_node_states']:
        return flask.render_template('not_found.html',
                info=info.get(),
                type='mn',
                id=pubkey,
                )

    mn = mn['master_node_states'][0]

    # Number of staked contributions
    mn['num_contributions'] = sum(len(x["locked_contributions"]) for x in mn["contributors"] if "locked_contributions" in x)
    # Number of unfilled, reserved contribution spots
    mn['num_reserved_spots'] = sum('reserved' in x and x["amount"] < x["reserved"] for x in mn["contributors"])
    # Available open contribution spots
    mn['num_open_spots'] = 0 if mn.get('total_reserved', mn['total_contributed']) >= mn['staking_requirement'] else max(0, 4 - mn['num_contributions'] - mn['num_reserved_spots'])
    if more_details:

        formatter = HtmlFormatter(cssclass="syntax-highlight", style="paraiso-dark")

        more_details = {

                'details_css': formatter.get_style_defs('.syntax-highlight'),
                'details_html': highlight(json.dumps(mn, indent="\t", sort_keys=True), JsonLexer(), formatter),
                }

    else:

        more_details = {}

    return flask.render_template('mn.html',
            info=info.get(),
            hf=hfinfo.get(),
            mn=mn,
            quorums=get_quorums(quos),
            **more_details,
            )


@app.route('/qr/<hex64:pubkey>')
def qr_mn_pubkey(pubkey):
    qr = qrcode.QRCode(
        box_size=5,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
    )
    qr.add_data(pubkey.upper())
    img = qr.make_image(
        fill_color="#1e1d48",
        back_color="#dbf7f5"
    )
    with BytesIO() as output:
        img.save(output, format="PNG")
        r = flask.make_response(output.getvalue())
    r.headers.set('Content-Type', 'image/png')
    return r


def parse_txs(txs_rpc):
    """Takes a tx_req(...).get() response and parses the embedded nested json into something useful

    This modifies the txs_rpc['txs'] values in-place.  Returns txs_rpc['txs'] if it exists, otherwise an empty list.
    """
    if txs_rpc is None or 'txs' not in txs_rpc:
        # None happens when the RPC request failed/timed out (e.g. busy daemon)
        return []

    for tx in txs_rpc['txs']:
        if 'type' not in tx and 'as_json' in tx:
            # We have serialized JSON data inside a field in the JSON, because of beldexd's
            # multiple incompatible JSON generators 🤮:
            tx = json.loads(tx["as_json"])
            del tx['as_json']
            # The "extra" field inside as_json is retardedly in per-byte integer values,
            # convert it to a hex string 🤮:
            tx['tx_extra_raw'] = bytes_to_hex(info['extra'])
            del info['extra']
            tx.update(info)
    return txs_rpc['txs']


def get_block_txs_future(lmq, beldexd, block):
    hashes = []
    if 'tx_hashes' in block:
        hashes += block['tx_hashes']
    miner_tx = block['block_header'].get('miner_tx_hash')
    if miner_tx:
        hashes.append(miner_tx)
    if 'info' not in block:
        try:
            block['info'] = json.loads(block["json"])
            if 'miner_tx' in block['info']:
                del block['info']['miner_tx']  # Doemn't include enough for us, we fetch it separately with extra interpretation instead
            del block["json"]
        except Exception as e:
            print("Something getting wrong: cannot parse block json for block {}: {}".format(block_height, e), file=sys.stderr)

    return tx_req(lmq, beldexd, hashes, cache_key='block')


@app.route('/block/<int:height>')
@app.route('/block/<int:height>/<int:more_details>')
@app.route('/block/<hex64:hash>')
@app.route('/block/<hex64:hash>/<int:more_details>')
def show_block(height=None, hash=None, more_details=False):
    lmq, beldexd = lmq_connection()
    info = _CachedInfoFuture(lmq, beldexd)
    hfinfo = FutureJSON(lmq, beldexd, 'rpc.hard_fork_info', 10)
    if height is not None:
        val = height
    elif hash is not None:
        val = hash

    block = None if val is None else block_with_txs_req(lmq, beldexd, val).get()
    if block is None:
        return flask.render_template("not_found.html",
                info=info.get(),
                hfinfo=hfinfo.get(),
                type='block',
                height=height,
                id=hash
                )

    next_block = None
    block_height = block['block_header']['height']
    txs = get_block_txs_future(lmq, beldexd, block)

    if info.get()['height'] > 1 + block_height:
        next_block = block_header_req(lmq, beldexd, '{}'.format(block_height + 1))

    if more_details:
        formatter = HtmlFormatter(cssclass="syntax-highlight", style="native")
        more_details = {
                'details_css': formatter.get_style_defs('.syntax-highlight'),
                'details_html': highlight(json.dumps(block, indent="\t", sort_keys=True), JsonLexer(), formatter),
                }
    else:
        more_details = {}

    transactions = [] if txs is None else parse_txs(txs.get()).copy()
    miner_tx = transactions.pop() if block['block_header'].get('miner_tx_hash') else None  
    return flask.render_template("block.html",
            info=info.get(),
            hfinfo=hfinfo.get(),
            block_header=block['block_header'],
            block=block,
            miner_tx=miner_tx,
            transactions=transactions,
            next_block=next_block.get() if next_block else None,
            **more_details,
            )
 

@app.route('/block/latest')
def show_block_latest():
    lmq, beldexd = lmq_connection()
    height = _CachedInfoFuture(lmq, beldexd).get()['height'] - 1
    return flask.redirect(flask.url_for('show_block', height=height), code=302)


@app.route('/tx/<hex64:txid>/rawjson')
def show_tx_rawjson(txid):
    """Syntax-highlighted raw tx JSON as a fragment, fetched on demand by the
    'Show raw details' toggle on the tx page (avoids a full page reload)."""
    lmq, beldexd = lmq_connection()
    txs = tx_req(lmq, beldexd, [txid]).get()
    if not txs or 'txs' not in txs or not txs['txs']:
        return flask.jsonify({'status': 'ERROR', 'message': 'tx not found'}), 404
    tx = parse_txs(txs)[0]
    formatter = HtmlFormatter(cssclass="syntax-highlight", style="paraiso-dark")
    return flask.jsonify({
        'status': 'OK',
        'css': formatter.get_style_defs('.syntax-highlight'),
        'html': highlight(json.dumps(tx, indent="\t", sort_keys=True), JsonLexer(), formatter),
    })


@app.route('/tx/<hex64:txid>')
@app.route('/tx/<hex64:txid>/<int:more_details>')
def show_tx(txid, more_details=False):
    lmq, beldexd = lmq_connection()
    info = _CachedInfoFuture(lmq, beldexd)
    txs = tx_req(lmq, beldexd, [txid]).get()

    if 'txs' not in txs or not txs['txs']:
        return flask.render_template('not_found.html',
                info=info.get(),
                type='tx',
                id=txid,
                )
    tx = parse_txs(txs)[0]

    # If this is a state change, see if we have the quorum stored to provide context
    testing_quorum = None
    if tx['version'] >= 4 and 'mn_state_change' in tx['extra']:
        testing_quorum = FutureJSON(lmq, beldexd, 'rpc.get_quorum_state', 60, cache_key='tx_state_change',
                args={ 'quorum_type': 0, 'start_height': tx['extra']['mn_state_change']['height'] })

    kindex_info = {} # { amount => { keyindex => {output-info} } }
    block_info_req = None
    if 'vin' in tx:
        if len(tx['vin']) == 1 and 'gen' in tx['vin'][0]:
            tx['coinbase'] = True
        elif tx['vin'] and config.enable_mixins_details:
            # Load output details for all outputs contained in the inputs
            outs_req = []
            for inp in tx['vin']:
                # Key positions are stored as offsets from the previous index rather than indices,
                # so de-delta them back into indices:
                if 'key_offsets' in inp['key'] and 'key_indices' not in inp['key']:
                    kis = []
                    inp['key']['key_indices'] = kis
                    kbase = 0
                    for koff in inp['key']['key_offsets']:
                        kbase += koff
                        kis.append(kbase)
                    del inp['key']['key_offsets']

            outs_req = [{"amount":inp['key']['amount'], "index":ki} for inp in tx['vin'] for ki in inp['key']['key_indices']]
            outputs = FutureJSON(lmq, beldexd, 'rpc.get_outs', args={
                'get_txid': True,
                'outputs': outs_req,
                }).get()
            if outputs and 'outs' in outputs and len(outputs['outs']) == len(outs_req):
                outputs = outputs['outs']
                # Also load block details for all of those outputs:
                block_info_req = FutureJSON(lmq, beldexd, 'rpc.get_block_header_by_height', args={
                    'heights': [o["height"] for o in outputs]
                })
                i = 0
                for inp in tx['vin']:
                    amount = inp['key']['amount']
                    if amount not in kindex_info:
                        kindex_info[amount] = {}
                    ki = kindex_info[amount]
                    for ko in inp['key']['key_indices']:
                        ki[ko] = outputs[i]
                        i += 1

    if more_details:
        formatter = HtmlFormatter(cssclass="syntax-highlight", style="paraiso-dark")
        more_details = {
                'details_css': formatter.get_style_defs('.syntax-highlight'),
                'details_html': highlight(json.dumps(tx, indent="\t", sort_keys=True), JsonLexer(), formatter),
                }
    else:
        more_details = {}

    block_info = {} # { height => {block-info} }
    if block_info_req:
        bi = block_info_req.get()
        if 'block_headers' in bi:
            for bh in bi['block_headers']:
                block_info[bh['height']] = bh


    if testing_quorum:
        testing_quorum = testing_quorum.get()
    if testing_quorum:
        if 'quorums' in testing_quorum and testing_quorum['quorums']:
            testing_quorum = testing_quorum['quorums'][0]['quorum']
        else:
            testing_quorum = None

    return flask.render_template('tx.html',
            info=info.get(),
            tx=tx,
            kindex_info=kindex_info,
            block_info=block_info,
            testing_quorum=testing_quorum,
            **more_details,
            )


@app.route('/quorums')
def show_quorums():
    lmq, beldexd = lmq_connection()
    info = _CachedInfoFuture(lmq, beldexd)
    quos = get_quorums_future(lmq, beldexd, info.get()['height'])

    return flask.render_template('quorums.html',
            info=info.get(),
            quorums=get_quorums(quos)
            )


base32z_dict = 'ybndrfg8ejkmcpqxot1uwisza345h769'
base32z_map = {base32z_dict[i]: i for i in range(len(base32z_dict))}

@app.route('/search')
def search():
    lmq, beldexd = lmq_connection()
    info = _CachedInfoFuture(lmq, beldexd)
    val = (flask.request.args.get('value') or '').strip()

    if val and len(val) < 10 and val.isdigit(): # Block height
        return flask.redirect(flask.url_for('show_block', height=val), code=301)

    if val and len(val) == 58 and val.endswith(".mnode") and val[51] in 'yoYO' and all(c in base32z_dict for c in val[0:52].lower()):
        v, bits = 0, 0
        for x in val[0:52].lower():
            v = (v << 5) | base32z_map[x]  # Arbitrary precision integers hurray!
        # The above loads 260 bytes (5 bits per char * 52 chars), but we only want 256:
        v >>= 4
        val = "{:64x}".format(v)
    if val and len(val) <= 68 and val.endswith(".bdx"):
        val = val.rstrip('.bdx')

    # BNS can be of length 64 however with txids, and sn pubkey's being of length 64 
    # I have removed it from the possible searches.
    if len(val) < 64 and all(c.isalnum() or c in '_-' for c in val):
        return flask.redirect(flask.url_for('show_bns', name=val), code=301) 
    elif not val or len(val) != 64 or any(c not in string.hexdigits for c in val):
        return flask.render_template('not_found.html',
                info=info.get(),
                type='bad_search',
                id=val,
                )

    # Initiate all the lookups at once, then redirect to whichever one responds affirmatively
    mnreq = mn_req(lmq, beldexd, val)
    blreq = block_header_req(lmq, beldexd, val, fail_okay=True)
    txreq = tx_req(lmq, beldexd, [val])

    mn = mnreq.get()
    if mn and 'master_node_states' in mn and mn['master_node_states']:
        return flask.redirect(flask.url_for('show_mn', pubkey=val), code=301)
    bl = blreq.get()
    if bl and 'block_header' in bl and bl['block_header']:
        return flask.redirect(flask.url_for('show_block', hash=val), code=301)
    tx = txreq.get()
    if tx and 'txs' in tx and tx['txs']:
        return flask.redirect(flask.url_for('show_tx', txid=val), code=301)

    return flask.render_template('not_found.html',
            info=info.get(),
            type='search',
            id=val,
            )

@app.route('/api/networkinfo')
def api_networkinfo():
    lmq, beldexd = lmq_connection()
    info = _CachedInfoFuture(lmq, beldexd)
    hfinfo = FutureJSON(lmq, beldexd, 'rpc.hard_fork_info', 10)

    info = info.get()
    data = {**info}
    hfinfo = hfinfo.get()
    data['current_hf_version'] = hfinfo['version']
    data['next_hf_height'] = hfinfo['earliest_height'] if 'earliest_height' in hfinfo else None
    return flask.jsonify({"data": data, "status": "OK"})

@app.route('/api/bnslookup')
def api_bnslookup():
    lmq, beldexd = lmq_connection()
    name = flask.request.args.get('name')

    blocked_names = {"beldex.bdx", "localhost.bdx", "mnode.bdx"}
    bns_data = {
        'available': True,
        'name': name,
        'bchat': "",
        'belnet': "",
        'wallet': "",
        'ethAddress': "",
    }

    if name in blocked_names:
        bns_data['available'] = False
        return flask.jsonify({"bnsData": bns_data, "status": "ok"})

    bnsinfo = bns_info(lmq, beldexd, name)
    result = bnsinfo.get('result')

    print(f"API BNS Lookup for name: {name}, Result: {result}")

    if result:
        info = result[0]
        bns_data.update({
            'owner': info.get('owner'),
            'exp_height': info.get('expiration_height'),
            'available': False,
        })

        field_map = {
            'bchat': 'encrypted_bchat_value',
            'belnet': 'encrypted_belnet_value',
            'wallet': 'encrypted_wallet_value',
            'eth_addr': 'encrypted_eth_addr_value',
        }
        for key, value in types.items():
            if len(bnsinfo[value]) != 0:
                decrypted_value = bns_decrypt(lmq, beldexd, name, key, bnsinfo[value]).get()
                if key == 'eth_addr':
                    bns_data['ethAddress'] = decrypted_value['value']
                else:
                    bns_data[key] = decrypted_value['value']

    return flask.jsonify({"bnsData": bns_data, "status": "ok"})

@app.route('/api/get_stats')
def api_get_stats():
    lmq, beldexd = lmq_connection()
    info = _CachedInfoFuture(lmq, beldexd)
    coinbase = FutureJSON(lmq, beldexd, 'admin.get_coinbase_tx_sum', 10, timeout=1, fail_okay=True,
            args={"height":0, "count":2**31-1}).get()

    info = info.get()
    data = {**info}
    height = data['height'] -1
    block = block_with_txs_req(lmq, beldexd, height).get()
    return flask.jsonify({
        "data": {
            "difficulty": data['difficulty'],
            "height": block['block_header']['height'],
            "burn": coinbase["burn_amount"],
            "total_emission": coinbase["emission_amount"],
            "last_timestamp": block['block_header']['timestamp'],
            "last_reward": block['block_header']['reward'],
        },
        "status": "ok"
    })

@app.route('/api/transaction_info/<hex64:txid>')
def show_tx_info(txid, more_details=False):
    lmq, beldexd = lmq_connection()
    info = _CachedInfoFuture(lmq, beldexd)
    txs = tx_req(lmq, beldexd, [txid]).get()

    if 'txs' not in txs or not txs['txs']:
        return flask.jsonify({
                "info":info.get(),
                "id":txid,
                })
    tx = parse_txs(txs)[0]

    # If this is a state change, see if we have the quorum stored to provide context
    testing_quorum = None
    if tx['version'] >= 4 and 'mn_state_change' in tx['extra']:
        testing_quorum = FutureJSON(lmq, beldexd, 'rpc.get_quorum_state', 60, cache_key='tx_state_change',
                args={ 'quorum_type': 0, 'start_height': tx['extra']['mn_state_change']['height'] })

    kindex_info = {} # { amount => { keyindex => {output-info} } }
    block_info_req = None
    if 'vin' in tx:
        if len(tx['vin']) == 1 and 'gen' in tx['vin'][0]:
            tx['coinbase'] = True
        elif tx['vin'] and config.enable_mixins_details:
            tx['coinbase'] = False
            # Load output details for all outputs contained in the inputs
            outs_req = []
            for inp in tx['vin']:
                # Key positions are stored as offsets from the previous index rather than indices,
                # so de-delta them back into indices:
                if 'key_offsets' in inp['key'] and 'key_indices' not in inp['key']:
                    kis = []
                    inp['key']['key_indices'] = kis
                    kbase = 0
                    for koff in inp['key']['key_offsets']:
                        kbase += koff
                        kis.append(kbase)
                    del inp['key']['key_offsets']

            outs_req = [{"amount":inp['key']['amount'], "index":ki} for inp in tx['vin'] for ki in inp['key']['key_indices']]
            outputs = FutureJSON(lmq, beldexd, 'rpc.get_outs', args={
                'get_txid': True,
                'outputs': outs_req,
                }).get()
            if outputs and 'outs' in outputs and len(outputs['outs']) == len(outs_req):
                outputs = outputs['outs']
                # Also load block details for all of those outputs:
                block_info_req = FutureJSON(lmq, beldexd, 'rpc.get_block_header_by_height', args={
                    'heights': [o["height"] for o in outputs]
                })
                i = 0
                for inp in tx['vin']:
                    amount = inp['key']['amount']
                    if amount not in kindex_info:
                        kindex_info[amount] = {}
                    ki = kindex_info[amount]
                    for ko in inp['key']['key_indices']:
                        ki[ko] = outputs[i]
                        i += 1

    if more_details:
        formatter = HtmlFormatter(cssclass="syntax-highlight", style="paraiso-dark")
        more_details = {
                'details_css': formatter.get_style_defs('.syntax-highlight'),
                'details_html': highlight(json.dumps(tx, indent="\t", sort_keys=True), JsonLexer(), formatter),
                }
    else:
        more_details = {}

    block_info = {} # { height => {block-info} }
    if block_info_req:
        bi = block_info_req.get()
        if 'block_headers' in bi:
            for bh in bi['block_headers']:
                block_info[bh['height']] = bh


    if testing_quorum:
        testing_quorum = testing_quorum.get()
    if testing_quorum:
        if 'quorums' in testing_quorum and testing_quorum['quorums']:
            testing_quorum = testing_quorum['quorums'][0]['quorum']
        else:
            testing_quorum = None

    infoBlock = info.get()
    data = tx
    data["current_height"] = infoBlock["height"]
    data["info"]["inputs"] = data["info"]["vin"]
    data["info"]["outputs"] = data["info"]["vout"]
    data["BDX_inputs"] = 0
    data["BDX_outputs"] = 0
    for inp in data["info"]["vin"]:
        x=0
        if 'key' in inp:
            inp["key"]["mixins"] = inp["key"]["key_indices"]
            data["BDX_inputs"] = data["BDX_inputs"] + inp["key"]["amount"]
            del inp["key"]["key_indices"]
            for kindex in inp["key"]["mixins"]:
                if inp["key"]["amount"] in kindex_info and kindex in kindex_info[inp["key"]["amount"]]:
                    oinfo = kindex_info[inp["key"]["amount"]][kindex]
                    binfo = block_info[oinfo["height"]]
                    oinfo["block_no"] = oinfo["height"]
                    oinfo["public_key"] = oinfo["key"]
                    oinfo["tx_hash"] = oinfo["txid"]
                    
                    del oinfo["txid"]
                    del oinfo["key"]
                    del oinfo["height"]
                    del oinfo["mask"]
                    del oinfo["unlocked"]
                    inp["key"]["mixins"][x] =oinfo
                    x=x+1
      
    for inp in data["info"]["vout"]:
        data["BDX_outputs"] = data["BDX_outputs"] + inp["amount"]
    
    del data["info"]["vin"]
    del data["info"]["output_unlock_times"]
    del data["info"]["vout"]
    del data["double_spend_seen"]
    
    return flask.jsonify({
            "data":data,
            "status": "success"
            })

circulating_supply_cache, circulating_supply_cache_expires = None, None
def fetch_circulating_supply():
    """Fetches the circulating supply (in whole BDX) from api.beldex.io, caching the result
    for 5 minutes. Returns None if the fetch fails and no cached value is available yet."""
    global circulating_supply_cache, circulating_supply_cache_expires
    if not circulating_supply_cache_expires or circulating_supply_cache_expires < time.time():
        try:
            r = requests.get("https://api.beldex.io/api/v1/bdx/circulating-supply", timeout=5)
            r.raise_for_status()
            circulating_supply_cache = float(r.text)
            circulating_supply_cache_expires = time.time() + 300
        except Exception as e:
            print("Failed to retrieve circulating supply: {}".format(e), file=sys.stderr)
    return circulating_supply_cache


@app.route('/api/emission')
def api_emission():
    lmq, beldexd = lmq_connection()
    info = _CachedInfoFuture(lmq, beldexd)
    coinbase = FutureJSON(lmq, beldexd, 'admin.get_coinbase_tx_sum', 10, timeout=1, fail_okay=True,
            args={"height":0, "count":2**31-1}).get()
    if not coinbase:
        return flask.jsonify(None)
    info = info.get()
    supply = fetch_circulating_supply()
    circulating_supply = (supply * 1_000_000_000 if supply is not None
            else coinbase["emission_amount"] - coinbase["burn_amount"])
    return flask.jsonify({
        "data": {
            "blk_no": info['height'] - 1,
            "burn": coinbase["burn_amount"],
            "circulating_supply": circulating_supply,
            "coinbase": coinbase["emission_amount"] - coinbase["burn_amount"],
            "emission": coinbase["emission_amount"],
            "fee": coinbase["fee_amount"]
        },
        "status": "success"
    })


@app.route('/api/master_node_stats')
def api_master_node_stats():
    lmq, beldexd = lmq_connection()
    info = _CachedInfoFuture(lmq, beldexd)
    stakinginfo = FutureJSON(lmq, beldexd, 'rpc.get_staking_requirement', 30)
    mns = get_mns_future(lmq, beldexd)
    mns = mns.get()
    if 'master_node_states' not in mns:
        return flask.jsonify({"status": "Error retrieving MN stats"}), 500
    mns = mns['master_node_states']

    stats = {'active': 0, 'funded': 0, 'awaiting_contribution': 0, 'decommissioned': 0, 'staked': 0}
    for mn in mns:
        if mn['funded']:
            stats['funded'] += 1
            if mn['active']:
                stats['active'] += 1
            else:
                stats['decommissioned'] += 1
        else:
            stats['awaiting_contribution'] += 1
        stats['staked'] += mn['total_contributed']

    stats['staked'] /= 1_000_000_000
    stats['mn_reward'] = 6.25
    stats['mn_reward_interval'] = stats['active']
    stakinginfo = stakinginfo.get()
    stats['mn_staking_requirement_full'] = stakinginfo['staking_requirement'] / 1_000_000_000
    stats['mn_staking_requirement_min'] = stats['mn_staking_requirement_full'] / 4

    info = info.get()
    stats['height'] = info['height']
    return flask.jsonify({"data": stats, "status": "OK"})


@app.route('/api/circulating_supply')
def api_circulating_supply():
    supply = fetch_circulating_supply()
    if supply is not None:
        return flask.jsonify(int(supply))
    lmq, beldexd = lmq_connection()
    coinbase = FutureJSON(lmq, beldexd, 'admin.get_coinbase_tx_sum', 10, timeout=1, fail_okay=True,
            args={"height":0, "count":2**31-1}).get()
    return flask.jsonify((coinbase["emission_amount"] - coinbase["burn_amount"]) // 1_000_000_000 if coinbase else None)


@app.route('/api/get_transaction_data/<hex64:txid>')
def api_get_transaction_data(txid):
    lmq, beldexd = lmq_connection()
    tx = tx_req_prune(lmq, beldexd, [txid]).get()
    txs = parse_txs(tx)
    return flask.jsonify({
        "status": tx['status'],
        "data": (txs[0] if txs else None)
        })

# FIXME: need better error handling here
@app.route('/api/transaction/<hex64:txid>')
def api_tx(txid):
    lmq, beldexd = lmq_connection()
    tx = tx_req(lmq, beldexd, [txid]).get()
    txs = parse_txs(tx)
    return flask.jsonify({
        "status": tx['status'],
        "data": (txs[0] if txs else None),
        })

@app.route('/api/block/<int:height>')
@app.route('/api/block/<hex64:blkid>')
def api_block(blkid=None, height=None):
    lmq, beldexd = lmq_connection()
    block = block_with_txs_req(lmq, beldexd, blkid if blkid is not None else height).get()
    txs = get_block_txs_future(lmq, beldexd, block)

    if 'block_header' in block:
        data = block['block_header'].copy()
        data["txs"] = parse_txs(txs.get()).copy()

    return flask.jsonify({
        "status": block['status'],
        "data": data,
        })

ticker_vs, ticker_vs_expires = [], None
ticker_cache, ticker_cache_expires = {}, None
@app.route('/api/prices')
@app.route('/api/price/<fiat>')
def api_price(fiat=None):
    global ticker_cache, ticker_cache_expires, ticker_vs, ticker_vs_expires
    # TODO: will need to change to 'beldex' when/if the ticker changes:
    ticker = 'beldex'

    if not ticker_cache or not ticker_cache_expires or ticker_cache_expires < time.time():
        if not ticker_vs_expires or ticker_vs_expires < time.time():
            try:
                x = requests.get("https://api.coingecko.com/api/v3/simple/supported_vs_currencies").json()
                if x:
                    ticker_vs = x
                    ticker_vs_expires = time.time() + 300
            except RuntimeError as e:
                print("Failed to retrieve vs currencies: {}".format(e), file=sys.stderr)
                # ignore failure because we might have an old value that is still usable

        if not ticker_vs:
            raise RuntimeError("Failed to retrieve CoinGecko currency list")

        try:
            x = requests.get("https://api.coingecko.com/api/v3/simple/price?ids={}&vs_currencies={}".format(
                ticker, ",".join(ticker_vs))).json()
        except RuntimeError as e:
            print("Failed to retrieve prices: {}".format(e), file=sys.stderr)

        if not x or ticker not in x or not x[ticker]:
            raise RuntimeError("Failed to retrieve prices from CoinGecko")
        ticker_cache = x[ticker]
        ticker_cache_expires = time.time() + 60

    if fiat is None:
        return flask.jsonify(ticker_cache)
    else:
        fiat = fiat.lower()
        return flask.jsonify({ fiat: ticker_cache[fiat] } if fiat in ticker_cache else {})
        

# ---------------------------------------------------------------------------
# /stats — blockchain statistics dashboard.
# Current values come straight from RPC; historical (yearly) series are built
# by sampling ~30 block headers at each year's midpoint plus per-year
# admin.get_coinbase_tx_sum ranges (burn), then cached for 6 hours.
# ---------------------------------------------------------------------------

_stats_history_cache = {'data': None, 'expiry': 0}

# Last fully-computed burn figures survive daemon busyness and restarts in a
# small JSON file next to the code, so the burn chart can show the previous
# values (marked with when they were calculated) instead of a pending note.
import os as _os
_STATS_DISK_CACHE = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), '.stats_cache.json')

def _load_disk_stats():
    try:
        with open(_STATS_DISK_CACHE) as f:
            return json.load(f)
    except Exception:
        return None

def _save_disk_stats(data):
    try:
        with open(_STATS_DISK_CACHE, 'w') as f:
            json.dump(data, f)
    except Exception as e:
        print("Failed to save stats cache: {}".format(e), file=sys.stderr)
_STATS_MAX_YEARS = 8          # how many calendar years of history to chart
_STATS_SAMPLE = 30            # block headers sampled per year
_BLOCK_TIME = 30              # target seconds per block

def _stats_history(lmq, beldexd, height, now_ts, include_burn=False):
    """Yearly series (estimates from sampled headers + real per-year burn from
    the admin coinbase RPC), cached for 6h. Returns None if the daemon cannot
    answer."""
    if _stats_history_cache['data'] is not None and _stats_history_cache['expiry'] > now_ts:
        return _stats_history_cache['data']

    try:
        # Anchor the year<->height mapping on the top block's real timestamp,
        # not the wall clock: while the daemon is still syncing the tip can be
        # months behind "now", which would shift every year bucket backwards.
        anchor_ts = now_ts
        try:
            top = FutureJSON(lmq, beldexd, 'rpc.get_block_header_by_height', 60,
                    cache_key='stats_top', args={'height': height - 1}).get()
            if top and top.get('block_header', {}).get('timestamp'):
                anchor_ts = top['block_header']['timestamp']
        except Exception:
            pass

        now_dt = datetime.fromtimestamp(anchor_ts, tz=timezone.utc)
        print("stats: anchor timestamp {} ({}), tip height {}".format(
                int(anchor_ts), now_dt.strftime('%Y-%m-%d'), height - 1), file=sys.stderr)
        years = list(range(now_dt.year - _STATS_MAX_YEARS + 1, now_dt.year + 1))
        # Approximate chain height at each Jan 1 from the target block time
        bounds = []
        for y in years:
            ts = datetime(y, 1, 1, tzinfo=timezone.utc).timestamp()
            bounds.append(max(0, height - 1 - int((anchor_ts - ts) // _BLOCK_TIME)))
        bounds.append(height - 1)  # current year runs to the tip

        # Fire everything up-front so the requests run in parallel
        header_futs, burn_futs = [], []
        for i, y in enumerate(years):
            start_h, end_h = bounds[i], bounds[i + 1]
            if end_h - start_h < 10:  # chain younger than this year
                print("stats: skipping year {}: only {} blocks in range".format(
                        y, end_h - start_h), file=sys.stderr)
                header_futs.append(None)
                burn_futs.append(None)
                continue
            mid = (start_h + end_h) // 2
            header_futs.append(FutureJSON(lmq, beldexd, 'rpc.get_block_headers_range', 21600,
                    cache_key='statsy{}'.format(y),
                    args={'start_height': mid, 'end_height': min(mid + _STATS_SAMPLE - 1, end_h)}))
            # Per-year coinbase sums are expensive for the daemon; only request
            # them once the cheap totals call reports the daemon's coinbase
            # cache is ready (include_burn), so we never pile heavy scans onto
            # a busy/syncing daemon.
            burn_futs.append(FutureJSON(lmq, beldexd, 'admin.get_coinbase_tx_sum', 21600,
                    cache_key='statsburn{}'.format(y), timeout=5, fail_okay=True,
                    args={'height': start_h, 'count': end_h - start_h}) if include_burn else None)

        # Master node registrations: registration_height of the currently
        # registered set, bucketed by (approximate) year
        mn_reg_fut = FutureJSON(lmq, beldexd, 'rpc.get_master_nodes', 21600,
                cache_key='stats_mn_reg',
                args={'all': False, 'fields': {'registration_height': True}})

        yearly = []
        for i, y in enumerate(years):
            fut = header_futs[i]
            if fut is None:
                continue
            headers = ((fut.get() or {}).get('headers')) or []
            if not headers:
                print("stats: year {} dropped: header sample RPC returned nothing "
                        "(daemon busy?)".format(years[i]), file=sys.stderr)
                continue
            start_h, end_h = bounds[i], bounds[i + 1]
            nblocks = end_h - start_h
            def avg(key):
                vals = [h.get(key, 0) for h in headers]
                return sum(vals) / len(vals) if vals else 0
            burn = None
            b = burn_futs[i].get() if burn_futs[i] is not None else None
            if b and 'burn_amount' in b:
                burn = round(b['burn_amount'] / 1e9)
            yearly.append({
                'label': str(y),
                'blocks': nblocks,
                'txs': round(avg('num_txes') * nblocks),
                'avg_block_size': round(avg('block_size')),
                'avg_reward': round(avg('reward') / 1e9, 4),
                'burned': burn,
            })

        # MN registration years (height -> approximate timestamp -> year)
        mn_years = []
        try:
            states = (mn_reg_fut.get() or {}).get('master_node_states', [])
            counts = {}
            for mn in states:
                rh = mn.get('registration_height')
                if rh is None:
                    continue
                ts = now_ts - (height - 1 - rh) * _BLOCK_TIME
                ry = datetime.fromtimestamp(ts, tz=timezone.utc).year
                counts[ry] = counts.get(ry, 0) + 1
            if counts:
                run = 0
                for y in range(min(counts), now_dt.year + 1):
                    run += counts.get(y, 0)
                    mn_years.append({'label': str(y), 'registered': counts.get(y, 0), 'cumulative': run})
        except Exception as e:
            print("stats: mn registration history unavailable: {}".format(e), file=sys.stderr)

        data = {'years': yearly, 'mn_years': mn_years} if yearly else None

        if data:
            fresh_burn_missing = any(y.get('burned') is None for y in yearly)
            if not fresh_burn_missing:
                # Full burn set fresh from the daemon: remember it for later
                _save_disk_stats({'years': [{'label': y['label'], 'burned': y['burned']}
                        for y in yearly], 'saved_at': now_ts})
            else:
                # Fill gaps from the last successful calculation, if any
                disk = _load_disk_stats()
                if disk:
                    saved = {y['label']: y.get('burned') for y in disk.get('years', [])}
                    filled = False
                    for y in yearly:
                        if y.get('burned') is None and saved.get(y['label']) is not None:
                            y['burned'] = saved[y['label']]
                            filled = True
                    if filled:
                        data['burn_asof'] = disk.get('saved_at')
            data['_burn_pending'] = fresh_burn_missing
    except Exception as e:
        print("stats history unavailable: {}".format(e), file=sys.stderr)
        data = None

    if data:
        _stats_history_cache['data'] = data
        burn_pending = data.pop('_burn_pending', False)
        # An incomplete series (newest year missing, e.g. its sample RPC timed
        # out) or pending burn figures: retry soon instead of caching for 6h.
        newest_missing = not data['years'] or \
                data['years'][-1]['label'] != str(datetime.fromtimestamp(
                    now_ts, tz=timezone.utc).year)
        if newest_missing:
            print("stats: newest year missing from series; will rebuild in 10 min",
                    file=sys.stderr)
        _stats_history_cache['expiry'] = now_ts + (600 if (burn_pending or newest_missing) else 6 * 3600)
    return data


@app.route('/stats')
def stats():
    lmq, beldexd = lmq_connection()
    inforeq = _CachedInfoFuture(lmq, beldexd)
    stake = FutureJSON(lmq, beldexd, 'rpc.get_staking_requirement', 10)
    mn_counts_req = FutureJSON(lmq, beldexd, 'rpc.get_master_nodes', 15, cache_key='counts',
            args={'all': False, 'fields': {'active': True, 'funded': True}})
    mempool = get_mempool_future(lmq, beldexd)
    coinbase = FutureJSON(lmq, beldexd, 'admin.get_coinbase_tx_sum', 120, timeout=1, fail_okay=True,
            args={"height": 0, "count": 2**31-1})

    info, stale_info = get_info_or_stale(inforeq)
    if info is None:
        print("daemon-busy page served for /stats: get_info timed out", file=sys.stderr)
        return flask.render_template('daemon_unavailable.html', info=None), 503
    info['testnet'] = info['nettype'] == 'testnet'
    info['devnet'] = info['nettype'] == 'devnet'
    height = info['height']
    now_ts = time.time()

    mn_counts = {'active': 0, 'awaiting': 0, 'decommissioned': 0}
    try:
        for mn in (mn_counts_req.get() or {}).get('master_node_states', []):
            if mn.get('active'):
                mn_counts['active'] += 1
            elif mn.get('funded'):
                mn_counts['decommissioned'] += 1
            else:
                mn_counts['awaiting'] += 1
    except Exception:
        pass

    try:
        mp = parse_mempool(mempool) or {}
    except Exception:
        mp = {}

    emission = coinbase.get()
    history = _stats_history(lmq, beldexd, height, now_ts,
            include_burn=bool(emission and emission.get('status') == 'OK'))

    bns_counts = info.get('bns_counts', 0)

    supply = fetch_circulating_supply()
    circulating_supply = supply * 1_000_000_000 if supply is not None else None

    # ---- derived insights ------------------------------------------------
    insights = []
    try:
        years = (history or {}).get('years') or []
        if len(years) >= 2:
            cur, prev = years[-1], years[-2]
            # Compare per-block activity so the partial current year is fair
            cur_rate = cur['txs'] / cur['blocks'] if cur['blocks'] else 0
            prev_rate = prev['txs'] / prev['blocks'] if prev['blocks'] else 0
            if prev_rate > 0:
                delta = (cur_rate - prev_rate) / prev_rate * 100
                insights.append({
                    'label': 'TX activity trend',
                    'value': '{:+.1f}%'.format(delta),
                    'tone': 'up' if delta >= 0 else 'down',
                    'desc': 'transactions per block in {} vs {} ({:.2f} vs {:.2f} tx/block)'.format(
                        cur['label'], prev['label'], cur_rate, prev_rate),
                })
            insights.append({
                'label': 'Est. daily transactions',
                'value': '{:,}'.format(round(cur_rate * 86400 / _BLOCK_TIME)),
                'tone': 'neutral',
                'desc': 'at the {} average of {:.2f} tx/block, one block every {}s'.format(
                    cur['label'], cur_rate, _BLOCK_TIME),
            })
            size_delta = ((cur['avg_block_size'] - prev['avg_block_size'])
                    / prev['avg_block_size'] * 100) if prev['avg_block_size'] else None
            if size_delta is not None:
                insights.append({
                    'label': 'Block size trend',
                    'value': '{:+.1f}%'.format(size_delta),
                    'tone': 'up' if size_delta >= 0 else 'down',
                    'desc': 'average block size {} vs {} ({:,} B vs {:,} B)'.format(
                        cur['label'], prev['label'], cur['avg_block_size'], prev['avg_block_size']),
                })
            insights.append({
                'label': 'New BDX per day',
                'value': '{:,.0f} BDX'.format(cur['avg_reward'] * 86400 / _BLOCK_TIME),
                'tone': 'neutral',
                'desc': 'current emission rate at {:.2f} BDX average block reward'.format(cur['avg_reward']),
            })
        mn_years = (history or {}).get('mn_years') or []
        if mn_years:
            reg_this_year = mn_years[-1]['registered']
            insights.append({
                'label': 'MN registrations in {}'.format(mn_years[-1]['label']),
                'value': '{:,}'.format(reg_this_year),
                'tone': 'up' if reg_this_year > 0 else 'neutral',
                'desc': 'still-registered nodes that joined this year (of {:,} total)'.format(
                    mn_years[-1]['cumulative']),
            })
        if emission and emission.get('status') == 'OK':
            circ = circulating_supply if circulating_supply is not None else emission['emission_amount'] - emission['burn_amount']
            if emission['emission_amount']:
                burn_pct = emission['burn_amount'] / emission['emission_amount'] * 100
                insights.append({
                    'label': 'Supply burned',
                    'value': '{:.2f}%'.format(burn_pct),
                    'tone': 'neutral',
                    'desc': '{:,.0f} BDX permanently removed from the {:,.0f} BDX ever emitted'.format(
                        emission['burn_amount'] / 1e9, emission['emission_amount'] / 1e9),
                })
            staked = mn_counts['active'] * (stake.get() or {}).get('staking_requirement', 0)
            if circ > 0 and staked > 0:
                insights.append({
                    'label': 'Supply staked',
                    'value': '{:.1f}%'.format(staked / circ * 100),
                    'tone': 'up',
                    'desc': '{:,.0f} BDX locked in {:,} active master nodes'.format(
                        staked / 1e9, mn_counts['active']),
                })
    except Exception as e:
        print("stats insights failed: {}".format(e), file=sys.stderr)

    # BNS registrations over years: the RPC only exposes the current total, so
    # persist a yearly snapshot and interpolate between known points (implicit
    # zero before the first charted year). Grows more accurate over time.
    total_bns = sum(bns_counts) if isinstance(bns_counts, (list, tuple)) else (bns_counts or 0)
    if history and history.get('years'):
        try:
            disk = _load_disk_stats() or {}
            snaps = disk.get('bns_snapshots', {})
            labels = [y['label'] for y in history['years']]
            cur_year = labels[-1]
            if total_bns and snaps.get(cur_year, 0) < total_bns:
                snaps[cur_year] = total_bns
                disk['bns_snapshots'] = snaps
                _save_disk_stats(disk)
            anchor_pts = [(-1, 0)] + sorted(
                    (labels.index(y), v) for y, v in snaps.items() if y in labels)
            series = []
            for i in range(len(labels)):
                lo = max((p for p in anchor_pts if p[0] <= i), key=lambda p: p[0])
                highs = [p for p in anchor_pts if p[0] > i]
                if not highs:
                    val = lo[1]
                else:
                    hi = min(highs, key=lambda p: p[0])
                    val = lo[1] + (hi[1] - lo[1]) * (i - lo[0]) / (hi[0] - lo[0])
                series.append(round(val))
            history['bns_years'] = [
                    {'label': l, 'cumulative': v} for l, v in zip(labels, series)]
        except Exception as e:
            print("stats: bns series failed: {}".format(e), file=sys.stderr)

    return flask.render_template('stats.html',
            insights=insights,
            stale_info=stale_info,
            info=info,
            stake=stake.get() or {'staking_requirement': 0},
            emission=emission,
            circulating_supply=circulating_supply,
            mn_counts=mn_counts,
            bns_counts=bns_counts,
            mempool_count=len(mp.get('txs', [])),
            hashrate=info.get('difficulty', 0) / _BLOCK_TIME,
            history=history,
            )
