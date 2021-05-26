import flask
from datetime import datetime, timedelta, timezone
import babel.dates
import json
import sys
import statistics
import string
import requests
from werkzeug.routing import BaseConverter
from lmq import FutureJSON, lmq_connection

app = flask.Flask(__name__)

class Hex64Converter(BaseConverter):
    def __init__(self, url_map):
        super().__init__(url_map)
        self.regex = "[0-9a-fA-F]{64}"

app.url_map.converters['hex64'] = Hex64Converter


@app.route('/page/<int:page>')
@app.route('/page/<int:page>/<int:per_page>')
@app.route('/range/<int:first>/<int:last>')
@app.route('/autorefresh/<int:refresh>')
@app.route('/')

def get_mempool_future(lmq, beldexd):
    return FutureJSON(lmq, beldexd, 'rpc.get_transaction_pool', 5, args={"tx_extra":True, "stake_info":True})
    
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