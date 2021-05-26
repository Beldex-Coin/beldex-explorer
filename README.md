# Beldex-Explorer
Block explorer using Beldex 4+ LMQ RPC interface that does everything through RPC requests.  Sexy,
awesome, safe.

## Prerequisite packages 

sudo apt install build-essential pkg-config libsodium-dev libzmq3-dev python3-dev python3-flask python3-babel python3-pygments

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