# Default configuration options for block explorer.
#
# To override settings add `config.whatever = ...` into `local_config.py`; adding settings *here*
# will often cause git conflicts.
#
# To override things that are specific to mainnet/testnet/etc. add `config.whatever = ...` lines
# into `mainnet.py`/`testnet.py`/etc.


# LMQ RPC endpoint of beldexd; can be a unix socket 'ipc:///path/to/beldexd.sock' (preferred) or a tcp
# socket 'tcp://127.0.0.1:5678'.  Typically you want this running with admin permission.
# Leave this as None here, and set it for each beldex in the mainnet.py/testnet.py/etc. script.
beldexd_rpc = 'ipc://beldex-explorer/testnet.sock'

# Default blocks per page for the index.
blocks_per_page=20
# Maximum blocks per page a user can request
max_blocks_per_page=100

# Some display and/or feature options:
pusher=False
key_image_checker=False
output_key_checker=False
autorefresh_option=True
enable_mixins_details=True

# Token-listing submission: where the /tokens/submit form is forwarded (the admin
# portal's ingest endpoint) and the shared secret it expects (must match the
# portal's INGEST_API_KEY). Set token_submit_url=None to disable forwarding.
token_submit_url='http://127.0.0.1:5001/api/submissions'
token_submit_api_key=''

# Whitelist JSON published by the admin portal, read for the "Whitelisted" tab.
token_whitelist_url='http://127.0.0.1:5001/whitelist.json'

# HMAC secret used to sign token-ownership challenges/grant tokens (see
# token_ownership.py). Must be set to a fixed value (e.g. in local_config.py)
# for any deployment running more than one worker process, or a challenge
# issued by one worker will be rejected by another. Leave None only for a
# single-process dev server.
token_verify_secret=None
# TTLs (seconds) for an issued ownership challenge and the grant token it
# produces once signed.
token_challenge_ttl=2400
token_ownership_ttl=1800

# URLs to networks other than the one we are on:
mainnet_url='https://explorer.beldex.io'
testnet_url='https://testnet.beldex.dev'
devnet_url='https://testnet.beldex.dev'

# Same as above, but these apply if we are on a .beldex URL:
belnet_mainnet_url='http://blocks.beldex'
belnet_testnet_url='http://testnet.beldex'
belnet_devnet_url='http://devnet.kcpyawm9se7trdbzncimdi5t7st4p5mh9i1mg7gkpuubi4k4ku1y.beldex'
