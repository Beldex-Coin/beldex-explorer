# Beldex-Explorer

Block explorer using the Beldex 4+ LMQ RPC interface that does everything through RPC requests.

This branch (`design-revamp-lagacy`) carries a **full design revamp of the server-rendered
Flask/Jinja frontend**, styled after beldex.io: near-black dot-grid canvas, Michroma display
type, Space Mono body, sharp white buttons, and Beldex green (#00d959) accents. Highlights:

- Header with top-right nav (Explorer / Master Nodes / Mempool / Quorums); search lives on the page
- Home page: hero + stat tiles (height, hard fork, POS, master nodes, supply, transactions in
  millions, burned BDX, BNS count, live BDX price, chain size), network-parameters panel,
  panelized blocks table, collapsible TX-type legend
- Master node lists on their own `/master_nodes` page; home shows count tiles only (faster load)
- Quorums page with tabbed quorum types and ellipsized pubkeys (`abc123…def456`)
- Master node & transaction pages with key/value detail panels, compact addresses, modern QR card
- Raw TX details load inline via `/tx/<txid>/rawjson` (no page reload)
- Resilience: RPC timeouts degrade pages gracefully; if the daemon is unreachable the explorer
  serves an auto-retrying "daemon busy" page instead of a 500

## Prerequisite packages

Debian/Ubuntu:

    sudo apt install build-essential pkg-config libsodium-dev libzmq3-dev python3-dev python3-flask python3-babel python3-pygments python3-qrcode python3-pysodium python3-sha3 python3-base58

macOS (Apple Silicon) — use the native ARM Homebrew (`/opt/homebrew`):

    /opt/homebrew/bin/brew install cmake pkg-config zeromq libsodium
    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt

## Building pylokimq

    git submodule update --init --recursive
    cd pylokimq
    mkdir build
    cd build
    cmake .. -DPYTHON_EXECUTABLE=$(which python)
    make -j6
    cd ../..
    ln -s pylokimq/build/pylokimq/pylokimq.cpython-*.so .

Notes:

- The compiled module is Python-version-specific: the `.so` name must match your interpreter
  (e.g. `pylokimq.cpython-312-darwin.so` for Python 3.12) or the import silently falls back to
  the empty source directory.
- On CMake 4+ add `-DCMAKE_POLICY_VERSION_MINIMUM=3.5`; if you upgrade the vendored pybind11
  (required for Python 3.12+), also add `-DSUBMODULE_CHECK=OFF`.
- On Apple Silicon force a native build if your toolchain defaults to x86_64:
  `arch -arm64 cmake .. -DCMAKE_OSX_ARCHITECTURES=arm64 ...` and verify with
  `file pylokimq.cpython-*.so` (must say `arm64`).

## Connecting to beldexd

Run beldexd with an LMQ admin socket and point the explorer at it. Either let the explorer's
default work by starting beldexd with:

    beldexd --lmq-local-control ipc:///path/to/beldex-explorer/beldexd/mainnet.sock

or set the socket you prefer in `mainnet.py`:

    config.beldexd_rpc = 'ipc:///Users/you/.beldex/beldexd.sock'

The flag's path and the config value must match, and beldexd must be started after the path is
chosen. While the daemon is busy syncing, RPCs may time out; the explorer shows a self-refreshing
"waiting for the daemon" page until it responds.

## Running in development

    ./run-mainnet.sh [port]

The script activates `.venv` if present, sets `DYLD_FALLBACK_LIBRARY_PATH` on macOS so ctypes
finds Homebrew's arm64 libsodium, and runs Flask on port 5000 by default. Note that plain
`flask run` caches templates — restart the process after template changes.

(Equivalent manual invocation: `FLASK_APP=mainnet flask run --port 5000`.)

## Setting up for production with uwsgi-emperor:

Do all of the above, but instead of running it with flask, set up uwsgi-emperor as follows:

    apt install uwsgi-emperor uwsgi-plugin-python3

in `/etc/uwsgi-emperor/emperor.ini` add configuration of:

    # vassals directory
    emperor = /etc/uwsgi-emperor/vassals
    cap = setgid,setuid
    emperor-tyrant = true

Create a "vassal" config for beldex-explorer, `/etc/uwsgi-emperor/vassals/beldex-explorer.ini`, containing:

    [uwsgi]
    chdir = /path/to/beldex-explorer
    socket = mainnet.wsgi
    plugins = python3,logfile
    processes = 4
    manage-script-name = true
    mount = /=mainnet:app

    logger = file:logfile=/path/to/beldex-explorer/mainnet.log

Set ownership of this user to whatever use you want it to run as, and set the group to `www-data` (so
that it can open the beldexd unix socket):

    chown www-data:www-data /etc/uwsgi-emperor/vassals/beldex-explorer.ini

In the beldex-explorer/mainnet.py, beldex-explorer/config.py, set:

    config.beldexd_rpc = 'ipc:///path/to/beldex-explorer/mainnet.sock'

## Setting up for HTTP Server with Apache:

Finally, proxy requests from the webserver to the wsgi socket.

    apt install apache2

For Apache `/etc/apache2/apache2.conf` do this with:

    # Allow access to static files (e.g. .css and .js):
    <Directory /path/to/beldex-explorer/static>
        Require all granted
    </Directory>
    DocumentRoot /path/to/beldex-explorer/static

    # Proxy everything else via the uwsgi socket:
    ProxyPassMatch "^/[^/]*\.(?:css|js)(?:$|\?)" !
    ProxyPass / unix:/path/to/beldex-explorer/mainnet.wsgi|uwsgi://uwsgi-mainnet-explorer/

(you will probably need to `a2enmod proxy_uwsgi` to enable the Apache modules that make that work).

That should be it: restart apache2 and uwsgi-emperor and you should be good to go.  If you want to
make uwsgi restart (for example because you are changing things) then it is sufficient to `touch
/etc/uwsgi-emperor/vassals/beldex-explorer.ini` to trigger a reload (you do not have to restart the
apache2/uwsgi-emperor layers).

If you want to set up a testnet or devnet explorer the procedure is essentially the same, but
using testnet.py or devnet.py pointing to a beldexd.sock from a testnet or devnet beldexd.

## Related branches

- `design-revamp` — the same visual revamp built as a React (Vite) SPA in `frontend/`, backed by
  JSON API v2 endpoints added to `explorer.py`. See that branch's `frontend/README.md`.
