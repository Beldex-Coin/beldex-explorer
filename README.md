# Beldex-Explorer

Block explorer for the Beldex network, built in two parts:

- **Backend** — Python/Flask service using the Beldex 4+ LMQ RPC interface; does everything through
  RPC requests. Serves the legacy HTML pages and a JSON API (`/api/*`, `/api/v2/*`).
- **Frontend** (`frontend/`) — React (Vite) single-page app with a full design revamp styled after
  beldex.io: dark dot-grid canvas, Michroma display type, Space Mono body, Beldex green accents.
  Consumes the backend JSON API. See [frontend/README.md](frontend/README.md).

## Backend

### Prerequisite packages

    sudo apt install build-essential pkg-config libsodium-dev libzmq3-dev python3-dev python3-flask python3-babel python3-pygments python3-qrcode python3-pysodium python3-sha3 python3-base58

### Building and running

Quick and dirty setup instructions for now:

    git submodule update --init --recursive
    cd pylokimq
    mkdir build
    cd build
    cmake ..
    make -j6
    cd ../..
    ln -s pylokimq/build/pylokimq/pylokimq.cpython-*.so .

(Note that we require a very recent python3-jinja package (2.11+), which may not be installed by the
above.)

You'll also need to run beldexd with `--lmq-local-control ipc:///path/to/beldex-explorer/mainnet.sock`.

### Running in debug mode

To run it in debug mode (production requires setting up a WSGI server, see below):

    FLASK_APP=explorer flask run --reload --debugger

This mode seems to be a bit flakey, though -- reloading, in particular, seems to break things and
make it just silently exit after a while.

## Frontend (React)

The React app lives in `frontend/` and talks to the backend JSON API.

### Development

    cd frontend
    npm install
    npm run dev

The dev server proxies `/api/*` to the Flask backend at `http://127.0.0.1:5000` (override with
`VITE_API_TARGET`). If the API is unreachable in dev, the UI falls back to built-in mock data so
every page stays previewable; force mock mode with `VITE_USE_MOCK=1 npm run dev`.

### Production build

    cd frontend
    npm run build

This outputs a static bundle to `frontend/dist/`. Serve it from your webserver with all
non-`/api` routes falling back to `index.html`, and proxy `/api/*` to the Flask/uwsgi backend
(see the Apache notes below).

### JSON API

The SPA consumes the v2 endpoints at the bottom of `explorer.py`:
`/api/v2/summary`, `/api/v2/blocks`, `/api/v2/block/<height|hash>`, `/api/v2/tx/<txid>`,
`/api/v2/mempool`, `/api/v2/master_nodes`, `/api/v2/mn/<pubkey>`, `/api/v2/quorums`,
`/api/v2/search`, `/api/v2/tokens` — plus the existing `/api/bnslookup`. The legacy HTML routes
remain available and unchanged.

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

Finally, serve the built React frontend and proxy API requests to the wsgi socket.

    apt install apache2

For Apache `/etc/apache2/apache2.conf` do this with:

    # Serve the built React app:
    <Directory /path/to/beldex-explorer/frontend/dist>
        Require all granted
        # SPA fallback: route unknown paths to index.html
        FallbackResource /index.html
    </Directory>
    DocumentRoot /path/to/beldex-explorer/frontend/dist

    # Proxy API requests to the uwsgi socket:
    ProxyPass /api unix:/path/to/beldex-explorer/mainnet.wsgi|uwsgi://uwsgi-mainnet-explorer/api

(you will probably need to `a2enmod proxy_uwsgi` to enable the Apache modules that make that work.
To keep serving the legacy HTML explorer instead, use the old `DocumentRoot
/path/to/beldex-explorer/static` configuration and proxy `/` to the uwsgi socket.)

That should be it: restart apache2 and uwsgi-emperor and you should be good to go.  If you want to
make uwsgi restart (for example because you are changing things) then it is sufficient to `touch
/etc/uwsgi-emperor/vassals/beldex-explorer.ini` to trigger a reload (you do not have to restart the
apache2/uwsgi-emperor layers).

If you want to set up a testnet or devnet explorer the procedure is essentially the same, but
using testnet.py or devnet.py pointing to a beldexd.sock from a testnet or devnet beldexd.
