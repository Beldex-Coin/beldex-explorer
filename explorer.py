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
from lmq import FutureJSON, lmq_connection

import base64
import nacl.encoding
import nacl.hash 
import pysodium
import sha3
import base58
from urllib.parse import urlparse

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

def format_asset_amount(raw, decimals):
    """Convert an asset's atomic-unit amount to a human-readable string using its
    decimal_point, with thousands separators and trailing zeros trimmed."""
    try:
        raw = int(raw)
        decimals = int(decimals)
    except (TypeError, ValueError):
        return raw if raw not in (None, '') else ''
    from decimal import Decimal
    value = Decimal(raw) / (Decimal(10) ** decimals)
    s = f"{value:,.{decimals}f}" if decimals > 0 else f"{value:,.0f}"
    if '.' in s:
        s = s.rstrip('0').rstrip('.')
    return s

# Simple in-memory cache for external price lookups: {price_url: (value, expiry)}.
# CoinGecko rate-limits aggressively, so we reuse a fetched price for a short TTL.
_price_cache = {}
_PRICE_CACHE_TTL = 60  # seconds

# Cache for the admin-portal whitelist JSON: {url: (whitelist_by_id, expiry)}.
# Fetched on /assets page loads; caching keeps every visitor from blocking on
# (and coupling our uptime to) the admin portal.
_whitelist_cache = {}
_WHITELIST_CACHE_TTL = 60  # seconds

def load_whitelist_by_id(whitelist_url):
    """Return {asset_id: entry} from the admin portal's whitelist JSON, cached for
    a short TTL. Returns {} (and logs) on any fetch/parse failure; on failure a
    still-valid cached copy is preferred over an empty result."""
    if not whitelist_url:
        return {}

    now = time.time()
    cached = _whitelist_cache.get(whitelist_url)
    if cached and cached[1] > now:
        return cached[0]

    try:
        whitelist_by_id = {}
        for entry in requests.get(whitelist_url, timeout=5).json().get('assets', []):
            aid = entry.get('asset_id', '')
            if aid:
                whitelist_by_id[aid] = entry
        _whitelist_cache[whitelist_url] = (whitelist_by_id, now + _WHITELIST_CACHE_TTL)
        return whitelist_by_id
    except (requests.RequestException, ValueError) as e:
        print("Failed to load assets whitelist from {}: {}".format(whitelist_url, e),
                file=sys.stderr)
        # Serve the last good copy if we have one, rather than dropping metadata.
        return cached[0] if cached else {}

def format_price_value(value):
    """Format a numeric price into a compact USD string (e.g. '$0.0453')."""
    try:
        value = float(value)
    except (TypeError, ValueError):
        return ''
    # Use more decimals for sub-dollar values so tiny prices stay legible.
    s = f"{value:,.8f}" if value < 1 else f"{value:,.4f}"
    if '.' in s:
        s = s.rstrip('0').rstrip('.')
    return '$' + s

def fetch_coingecko_price(price_url):
    """Fetch the current price for an asset from a CoinGecko API URL published in
    the whitelist. Only CoinGecko URLs are supported today. Returns a formatted
    price string (e.g. '$0.0453') or '' on any failure. Results are cached briefly."""
    if not price_url:
        return ''
    host = (urlparse(price_url).hostname or '').lower()
    if host != 'coingecko.com' and not host.endswith('.coingecko.com'):
        return ''

    now = time.time()
    cached = _price_cache.get(price_url)
    if cached and cached[1] > now:
        return cached[0]

    price = ''
    try:
        data = requests.get(price_url, timeout=5).json()
        # /coins/markets returns a list of objects with 'current_price'.
        if isinstance(data, list) and data:
            price = format_price_value(data[0].get('current_price'))
        # /simple/price returns {id: {vs_currency: value}}.
        elif isinstance(data, dict) and data:
            first = next(iter(data.values()))
            if isinstance(first, dict) and first:
                price = format_price_value(next(iter(first.values())))
    except (requests.RequestException, ValueError, StopIteration, AttributeError) as e:
        print("Failed to fetch price from {}: {}".format(price_url, e), file=sys.stderr)

    _price_cache[price_url] = (price, now + _PRICE_CACHE_TTL)
    return price

def asset_display_dict(a):
    """Return a display-ready copy of a daemon asset dict (formatted supplies).
    Returns None if given None. Does not mutate the cached daemon response."""
    if not a:
        return None
    d = dict(a)
    d['asset_id'] = a.get('asset_id', '')
    d['current_supply'] = format_asset_amount(a.get('current_supply'), a.get('decimal_point'))
    d['total_max_supply'] = format_asset_amount(a.get('total_max_supply'), a.get('decimal_point'))
    return d

# Get asset info from beldexd
def get_asset_info(asset_id):
    """Fetch asset info from daemon."""
    if not asset_id:
        return None

    lmq, beldexd = lmq_connection()
    result = FutureJSON(lmq, beldexd, 'rpc.get_asset_info', 5, cache_key=asset_id,
            args={'asset_id': asset_id}).get()

    if not result:
        return None

    if result.get('status') not in (None, 'OK'):
        return None

    assets = result.get('assets')
    if isinstance(assets, list):
        return assets[0] if assets else None

    return result

@app.template_filter('format_datetime')
def format_datetime(value, format='long'):
    print(value)
    return babel.dates.format_datetime(value, format, tzinfo=babel.dates.get_timezone('UTC'))

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
@app.template_filter('bytes_to_hex')
def bytes_to_hex(b):
    return "".join("{:02x}".format(x) for x in b)

@app.template_filter('base32z')
def base32z(hex):
    return b32encode(b16decode(hex, casefold=True)).translate(
            bytes.maketrans(
                b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
                b'ybndrfg8ejkmcpqxot1uwisza345h769')).decode().rstrip('=')


@app.template_filter('source_name')
def source_name(url):
    """Turn a source URL into a short, readable provider name for link text,
    e.g. 'https://www.coingecko.com/...' -> 'Coingecko'. Non-URL values (a plain
    name like 'CoinGecko') are returned unchanged."""
    if not url or not str(url).startswith('http'):
        return url
    host = urlparse(url).hostname or url
    host = host[4:] if host.startswith('www.') else host
    labels = host.split('.')
    # Registrable label: second-to-last for host.tld, else the first label.
    name = labels[-2] if len(labels) >= 2 else labels[0]
    return name.capitalize()


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

@app.route('/style.css')
def css():
    return flask.send_from_directory('static', 'style.css')


def get_mns_future(lmq, beldexd):
    return FutureJSON(lmq, beldexd, 'rpc.get_master_nodes', 5,
            args={
                'all': False,
                'fields': { x: True for x in ('master_node_pubkey', 'requested_unlock_height', 'last_reward_block_height',
                    'last_reward_transaction_index', 'active', 'funded', 'earned_downtime_blocks',
                    'master_node_version', 'contributors', 'total_contributed', 'total_reserved',
                    'staking_requirement', 'portions_for_operator', 'operator_address', 'pubkey_ed25519',
                    'last_uptime_proof', 'state_height', 'swarm_id') } })

def get_mns(mns_future, info_future):
    info = info_future.get()
    awaiting_mns, active_mns, inactive_mns = [], [], []
    mn_states = mns_future.get()
    mn_states = mn_states['master_node_states'] if 'master_node_states' in mn_states else []
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
    inforeq = FutureJSON(lmq, beldexd, 'rpc.get_info', 1)
    stake = FutureJSON(lmq, beldexd, 'rpc.get_staking_requirement', 10)
    base_fee = FutureJSON(lmq, beldexd, 'rpc.get_fee_estimate', 10)
    hfinfo = FutureJSON(lmq, beldexd, 'rpc.hard_fork_info', 10)
    mempool = get_mempool_future(lmq, beldexd)
    mns = get_mns_future(lmq, beldexd)
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
    info = inforeq.get()
    height = info['height']
    info['testnet']  = info['nettype'] == 'testnet'
    info['devnet']   = info['nettype'] == 'devnet'
    bns = info['bns_counts']
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

    blocks = FutureJSON(lmq, beldexd, 'rpc.get_block_headers_range', cache_key='main', args={
        'start_height': start_height,
        'end_height': end_height,
        'get_tx_hashes': True,
        }).get()['headers']

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

    # Clean up the MN data a bit to make things easier for the templates
    awaiting_mns, active_mns, inactive_mns = get_mns(mns, inforeq)

    return flask.render_template('index.html',
            bns=bns,
            info=info,
            stake=stake.get(),
            fees=base_fee.get(),
            emission=coinbase.get(),
            hf=hfinfo.get(),
            active_mns=active_mns,
            inactive_mns=inactive_mns,
            awaiting_mns=awaiting_mns,
            blocks=blocks,
            block_size_median=statistics.median(b['block_size'] for b in blocks),
            page=page,
            per_page=per_page,
            custom_per_page=custom_per_page,
            mempool=parse_mempool(mempool),
            checkpoints=checkpoints.get(),
            refresh=refresh,
            )


@app.route('/txpool')
def mempool():
    lmq, beldexd = lmq_connection()
    info = FutureJSON(lmq, beldexd, 'rpc.get_info', 1)
    mempool = get_mempool_future(lmq, beldexd)

    return flask.render_template('mempool.html',
            info=info.get(),
            mempool=parse_mempool(mempool),
            )

@app.route('/assets')
@app.route('/assets/<int:offset>')
@app.route('/assets/<int:offset>/<int:count>')
def assets(offset=0, count=20):
    if count <= 0:
        count = 20
    if offset < 0:
        offset = 0
    lmq, beldexd = lmq_connection()
    info = FutureJSON(lmq, beldexd, 'rpc.get_info', 1)

    # All assets: the daemon's get_asset_list only returns IDs, so we fetch the
    # full descriptor for each id via get_asset_info (fired in parallel).
    asset_list = FutureJSON(lmq, beldexd, 'rpc.get_asset_list', 5,
            args={'offset': offset, 'count': count}).get() or {}
    asset_ids = asset_list.get('asset_ids', [])
    total_count = asset_list.get('total_count', len(asset_ids))

    info_futures = [
        FutureJSON(lmq, beldexd, 'rpc.get_asset_info', 5, cache_key=aid,
            args={'asset_id': aid})
        for aid in asset_ids]

    all_assets = []
    for aid, fut in zip(asset_ids, info_futures):
        a = fut.get() or {}
        all_assets.append({
            'name': a.get('full_name', ''),
            'ticker': a.get('ticker', ''),
            'asset_id': a.get('asset_id', aid),
            # price/source require an external price feed / DEX, which Beldex does
            # not have yet, so leave them empty for now (rendered as "No data").
            'price': '',
            'source': '',
            # Full descriptor fields, shown in the expandable detail panel.
            'full_name': a.get('full_name', ''),
            'total_max_supply': format_asset_amount(a.get('total_max_supply'), a.get('decimal_point')),
            'current_supply': format_asset_amount(a.get('current_supply'), a.get('decimal_point')),
            'decimal_point': a.get('decimal_point', ''),
            'meta_info': a.get('meta_info', ''),
            'owner': a.get('owner', ''),
            # off-chain metadata (from the whitelist later); empty for on-chain-only assets
            'social': '',
            'logo': '',
            })

    # Whitelist: curated off-chain metadata (logo, source, socials, ...) published
    # by the admin portal, keyed by asset_id (cached for a short TTL).
    whitelist_by_id = load_whitelist_by_id(getattr(config, 'assets_whitelist_url', None))

    # When an on-chain asset is also whitelisted, overlay the curated off-chain
    # fields (logo, price, source, social) onto its All Assets row.
    for a in all_assets:
        entry = whitelist_by_id.get(a['asset_id'])
        if entry:
            socials = entry.get('socials') or {}
            a['logo'] = entry.get('logo', '') or a['logo']
            a['source'] = entry.get('source', '') or a['source']
            # Live price pulled from the whitelist's price_url (CoinGecko today).
            a['price'] = fetch_coingecko_price(entry.get('price_url', '')) or a['price']
            # macro renders a single social link; prefer the website
            a['social'] = entry.get('website') or socials.get('twitter', '') or a['social']

    # Whitelisted tab shows only the assets that are both curated and on-chain.
    whitelisted = [a for a in all_assets if a['asset_id'] in whitelist_by_id]

    page = offset // count
    total_pages = max(1, -(-total_count // count))  # ceil division

    return flask.render_template('assets.html',
            info=info.get(),
            whitelisted=whitelisted,
            assets=all_assets,
            assets_total=total_count,
            offset=offset,
            count=count,
            page=page,
            total_pages=total_pages,
            )

ASSET_SOCIAL_FIELDS = ['whitepaper', 'github', 'telegram', 'discord', 'twitter',
                       'linkedin', 'medium', 'reddit', 'facebook',
                       'slack', 'wechat', 'bitcointalk', 'ticketing', 'opensea']

# Fields the requester must fill in (mirrors the `required` inputs in the form).
ASSET_REQUIRED_FIELDS = ['requester_name', 'requester_email', 'project_name',
                         'website', 'email', 'description']


@app.route('/assets/submit', methods=['GET', 'POST'])
@app.route('/assets/submit/<string:asset_id>', methods=['GET', 'POST'])
def assets_submit(asset_id=None):
    lmq, beldexd = lmq_connection()
    info = FutureJSON(lmq, beldexd, 'rpc.get_info', 1)
    submit_result = None

    if flask.request.method == 'POST':
        form = flask.request.form
        asset_id = (form.get('asset_id') or asset_id or '').strip()

        if form.get('company'):
            # Honeypot filled -> silently accept (drop the bot submission).
            submit_result = {'ok': True, 'message': 'Your submission was received and is pending review.'}
        elif not asset_id or get_asset_info(asset_id) is None:
            submit_result = {'ok': False, 'message': 'Please provide a valid asset ID (it must exist on-chain).'}
        elif not all(form.get(f, '').strip() for f in ASSET_REQUIRED_FIELDS):
            submit_result = {'ok': False, 'message': 'Please fill in all required fields.'}
        elif sum(1 for k in ASSET_SOCIAL_FIELDS if form.get(k, '').strip()) < 1:
            submit_result = {'ok': False, 'message': 'Please provide at least 1 social link.'}
        else:
            payload = {
                'asset_id': asset_id,
                'requester_name': form.get('requester_name', ''),
                'requester_email': form.get('requester_email', ''),
                'metadata': {
                    'project_name': form.get('project_name', ''),
                    'website': form.get('website', ''),
                    'email': form.get('email', ''),
                    'sector': (form.get('sector_other', '').strip()
                               if form.get('sector', '') == 'Other'
                               else form.get('sector', '')),
                    'description': form.get('description', ''),
                    'logo': form.get('logo', '').strip(),
                    'price_url': form.get('price_url', ''),
                    'source': form.get('source', ''),
                    'explorer_url': form.get('explorer_url', ''),
                    'notes': form.get('notes', ''),
                    'socials': {k: form.get(k, '') for k in ASSET_SOCIAL_FIELDS},
                },
                'ownership': {
                    'challenge': form.get('challenge', ''),
                    'signature': form.get('signature', ''),
                    'verified': False,
                },
            }
            url = getattr(config, 'assets_submit_url', None)
            key = getattr(config, 'assets_submit_api_key', '') or ''
            if not url:
                submit_result = {'ok': False, 'message': 'Submission endpoint is not configured.'}
            else:
                try:
                    resp = requests.post(url, json=payload, headers={'X-Api-Key': key}, timeout=10)
                    if resp.status_code in (200, 201, 202):
                        submit_result = {'ok': True, 'message': 'Your submission was received and is pending review.'}
                    else:
                        submit_result = {'ok': False, 'message': 'The review service rejected the submission (HTTP {}).'.format(resp.status_code)}
                except requests.RequestException:
                    submit_result = {'ok': False, 'message': 'Could not reach the review service. Please try again later.'}

    asset = None
    asset_not_found = False

    if asset_id:
        asset = asset_display_dict(get_asset_info(asset_id))

        if asset is None:
            asset_not_found = True

    return flask.render_template(
        "assets_submit.html",
        info=info.get(),
        asset=asset,
        asset_id=asset_id,
        asset_not_found=asset_not_found,
        submit_result=submit_result,
    )


@app.route('/api/asset_info/<string:asset_id>')
def api_asset_info(asset_id):
    """JSON lookup used by the submission form to auto-fill on-chain fields."""
    asset = asset_display_dict(get_asset_info(asset_id))
    if asset is None:
        return flask.jsonify({'found': False})
    return flask.jsonify({'found': True, 'asset': asset})


@app.route('/api/submission/<string:asset_id>')
def api_submission(asset_id):
    """Proxy for the admin portal's GET /api/submissions/<asset_id>. Runs
    server-side so the X-Api-Key stays secret; used by the submission form to
    pre-fill fields from the most recent previous submission for this asset."""
    submit_url = getattr(config, 'assets_submit_url', None)
    key = getattr(config, 'assets_submit_api_key', '') or ''
    if not submit_url:
        return flask.jsonify({'found': False}), 200

    # assets_submit_url is the collection endpoint (…/api/submissions); the
    # per-asset lookup lives at …/api/submissions/<asset_id>.
    url = submit_url.rstrip('/') + '/' + asset_id
    try:
        resp = requests.get(url, headers={'X-Api-Key': key}, timeout=10)
    except requests.RequestException as e:
        print("Failed to fetch submission for {}: {}".format(asset_id, e), file=sys.stderr)
        return flask.jsonify({'found': False, 'error': 'lookup_failed'}), 502

    if resp.status_code == 404:
        return flask.jsonify({'found': False}), 200
    if resp.status_code == 401:
        print("Submission lookup unauthorized (check assets_submit_api_key)", file=sys.stderr)
        return flask.jsonify({'found': False, 'error': 'unauthorized'}), 200
    try:
        return flask.jsonify(resp.json()), 200
    except ValueError:
        return flask.jsonify({'found': False, 'error': 'bad_response'}), 502


@app.route('/master_nodes')
def mns():
    lmq, beldexd = lmq_connection()
    info = FutureJSON(lmq, beldexd, 'rpc.get_info', 1)
    awaiting, active, inactive = get_mns(get_mns_future(lmq, beldexd), info)

    return flask.render_template('master_nodes.html',
        info=info.get(),
        active_mns=active,
        awaiting_mns=awaiting,
        inactive_mns=inactive,
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
    info = FutureJSON(lmq, beldexd, 'rpc.get_info', 1)

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
    info = FutureJSON(lmq, beldexd, 'rpc.get_info', 1)
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
    if 'txs' not in txs_rpc:
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
    info = FutureJSON(lmq, beldexd, 'rpc.get_info', 1)
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
    height = FutureJSON(lmq, beldexd, 'rpc.get_info', 1).get()['height'] - 1
    return flask.redirect(flask.url_for('show_block', height=height), code=302)


@app.route('/tx/<hex64:txid>')
@app.route('/tx/<hex64:txid>/<int:more_details>')
def show_tx(txid, more_details=False):
    lmq, beldexd = lmq_connection()
    info = FutureJSON(lmq, beldexd, 'rpc.get_info', 1)
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
    info = FutureJSON(lmq, beldexd, 'rpc.get_info', 1)
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
    info = FutureJSON(lmq, beldexd, 'rpc.get_info', 1)
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
    if val.endswith(".bdx"):
        val = val[:-4]

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
    info = FutureJSON(lmq, beldexd, 'rpc.get_info', 1)
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

        for key, encrypted_field in field_map.items():
            encrypted_value = info.get(encrypted_field)
            if encrypted_value:
                decrypted = bns_decrypt(lmq, beldexd, name, key, encrypted_value).get()
                output_key = 'ethAddress' if key == 'eth_addr' else key
                bns_data[output_key] = decrypted.get('value', "")

    return flask.jsonify({"bnsData": bns_data, "status": "ok"})

@app.route('/api/get_stats')
def api_get_stats():
    lmq, beldexd = lmq_connection()
    info = FutureJSON(lmq, beldexd, 'rpc.get_info', 1)
    coinbase = FutureJSON(lmq, beldexd, 'admin.get_coinbase_tx_sum', 10, timeout=1, fail_okay=True,
            args={"height":0, "count":2**31-1}).get()

    info = info.get()
    data = {**info}
    height = data['height'] -1
    block = block_with_txs_req(lmq, beldexd, height).get()
    return flask.jsonify({
        "data": {
            "difficulty": data.get('difficulty', 0),
            "bns_count": data.get('bns_counts',0),
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
    info = FutureJSON(lmq, beldexd, 'rpc.get_info', 1)
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

@app.route('/api/emission')
def api_emission():
    lmq, beldexd = lmq_connection()
    info = FutureJSON(lmq, beldexd, 'rpc.get_info', 1)
    coinbase = FutureJSON(lmq, beldexd, 'admin.get_coinbase_tx_sum', 10, timeout=1, fail_okay=True,
            args={"height":0, "count":2**31-1}).get()
    if not coinbase:
        return flask.jsonify(None)
    info = info.get()
    return flask.jsonify({
        "data": {
            "blk_no": info['height'] - 1,
            "burn": coinbase["burn_amount"],
            "circulating_supply": coinbase["emission_amount"] - coinbase["burn_amount"],
            "coinbase": coinbase["emission_amount"] - coinbase["burn_amount"],
            "emission": coinbase["emission_amount"],
            "fee": coinbase["fee_amount"]
        },
        "status": "success"
    })


@app.route('/api/master_node_stats')
def api_master_node_stats():
    lmq, beldexd = lmq_connection()
    info = FutureJSON(lmq, beldexd, 'rpc.get_info', 1)
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
        
