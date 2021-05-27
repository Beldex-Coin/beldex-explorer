import flask
from datetime import datetime, timedelta, timezone
import babel.dates
import json
import sys
import statistics
import string
import requests
from werkzeug.routing import BaseConverter
import subprocess

import config
import local_config
from lmq import FutureJSON, lmq_connection

# Make a dict of config.* to pass to templating
conf = {x: getattr(config, x) for x in dir(config) if not x.startswith('__')}

git_rev = subprocess.run(["git", "rev-parse", "--short=9", "HEAD"], stdout=subprocess.PIPE, text=True)
if git_rev.returncode == 0:
    git_rev = git_rev.stdout.strip()
else:
    git_rev = "(unknown)"

app = flask.Flask(__name__)

class Hex64Converter(BaseConverter):
    def __init__(self, url_map):
        super().__init__(url_map)
        self.regex = "[0-9a-fA-F]{64}"

app.url_map.converters['hex64'] = Hex64Converter

# For some inexplicable reason some hex fields are provided as array of byte integer values rather
# than hex.  This converts such a monstrosity to hex.
@app.template_filter('bytes_to_hex')
def bytes_to_hex(b):
    return "".join("{:02x}".format(x) for x in b)



@app.route('/page/<int:page>')
@app.route('/page/<int:page>/<int:per_page>')
@app.route('/range/<int:first>/<int:last>')
@app.route('/autorefresh/<int:refresh>')
@app.route('/')

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

def get_mempool_future(lmq, beldexd):
    return FutureJSON(lmq, beldexd, 'rpc.get_transaction_pool', 5, args={"tx_extra":True, "stake_info":True})

def parse_mempool(mempool_future):
    # mempool RPC return values are about as nasty as can be.  For each mempool tx, we get back
    # *both* binary+hex encoded values and JSON-encoded values slammed into a string, which means we
    # have to invoke an *extra* JSON parser for each tx.  This is terrible.
    mp = mempool_future.get()
    if 'transactions' in mp:
        # If we have a cached value we have already sorted it
        if '_sorted' not in mp:
            mp['transactions'].sort(key=lambda tx: (tx['receive_time'], tx['id_hash']))
            mp['_sorted'] = True

        for tx in mp['transactions']:
            tx['info'] = json.loads(tx["tx_json"])
    else:
        mp['transactions'] = []
    return mp

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

    # Permalinked block range:
    if first is not None and last is not None and 0 <= first <= last and last <= first + 99:
        start_height, end_height = first, last
        if end_height - start_height + 1 != per_page:
            per_page = end_height - start_height + 1;
            custom_per_page = '/{}'.format(per_page)
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
            txids.append(b['miner_tx_hash'])
            if 'tx_hashes' in b:
                txids += b['tx_hashes']
        txs = parse_txs(tx_req(lmq, beldexd, txids, cache_key='mempool').get())
        i = 0
        for tx in txs:
            # TXs should come back in the same order so we can just skip ahead one when the block
            # height changes rather than needing to search for the block
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

def tx_req(lmq, beldexd, txids, cache_key='single', **kwargs):
    return FutureJSON(lmq, beldexd, 'rpc.get_transactions', cache_seconds=10, cache_key=cache_key,
            args={
                "txs_hashes": txids,
                "decode_as_json": True,
                "tx_extra": True,
                "prune": True,
                "stake_info": True,
                },
            **kwargs)

def parse_txs(txs_rpc):
    """Takes a tx_req(...).get() response and parses the embedded nested json into something useful

    This modifies the txs_rpc['txs'] values in-place.  Returns txs_rpc['txs'] if it exists, otherwise an empty list.
    """
    if 'txs' not in txs_rpc:
        return []

    for tx in txs_rpc['txs']:
        if 'info' not in tx:
            # We have serialized JSON data inside a field in the JSON, because of beldexd's
            # multiple incompatible JSON generators 🤮:
            tx['info'] = json.loads(tx["as_json"])
            del tx['as_json']
            # The "extra" field inside as_json is retardedly in per-byte integer values,
            # convert it to a hex string 🤮:
            tx['info']['extra'] = bytes_to_hex(tx['info']['extra'])
    return txs_rpc['txs']

