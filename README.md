# Beldex-Explorer
Block explorer using Beldex 4+ LMQ RPC interface that does everything through RPC requests.  Sexy,
awesome, safe.

## Prerequisite packages 

    sudo apt install build-essential pkg-config libsodium-dev libzmq3-dev python3-dev python3-flask python3-babel python3-pygments python3-qrcode

## Building and running

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

## Running in debug mode

To run it in debug mode (production requires setting up a WSGI server, see below):

    FLASK_APP=explorer flask run --reload --debugger

This mode seems to be a bit flakey, though -- reloading, in particular, seems to break things and
make it just silently exit after a while.

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

 For Apache  `/etc/apache2/apache2.conf` do this with:

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
