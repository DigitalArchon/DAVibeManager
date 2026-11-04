#!/usr/bin/env python3
"""A stand-in for tor, run as tor is (-f torrc --defaults-torrc x): its control socket, the cookie
login, bootstrap, and onion services, as much of tor's control protocol as the app speaks.
FAKE_TOR_LOG: where the commands it was sent are written. ADD_ONION answers with the address
worked out from the key it was given, as tor does (the test gives the seed's address in
FAKE_TOR_ADDRESS). It exits when the controller that took ownership goes."""

import asyncio
import hashlib
import hmac
import os
import re
import secrets
import sys

S2C = b"Tor safe cookie authentication server-to-controller hash"
C2S = b"Tor safe cookie authentication controller-to-server hash"


def torrc():
    path = sys.argv[sys.argv.index("-f") + 1]
    conf = {}
    for line in open(path):
        key, _, value = line.strip().partition(" ")
        conf[key] = value
    return conf


async def main():
    conf = torrc()
    data = conf["DataDirectory"].strip('"')
    control = re.match(r'unix:"(.*)"', conf["ControlPort"]).group(1)
    cookie_path = os.path.join(data, "control_auth_cookie")
    cookie = secrets.token_bytes(32)
    with open(cookie_path, "wb") as f:
        f.write(cookie)
    log = open(os.environ.get("FAKE_TOR_LOG", os.devnull), "a")
    print("[notice] Bootstrapped 0% (starting): Starting", flush=True)
    gone = asyncio.get_running_loop().create_future()

    async def client(reader, writer):
        nonce = b""
        owned = False

        def say(text):
            writer.write(text.encode() + b"\r\n")
        while line := await reader.readline():
            cmd = line.decode().strip()
            log.write(cmd + "\n")
            log.flush()
            word = cmd.split(" ", 1)[0]
            if word == "PROTOCOLINFO":
                say("250-PROTOCOLINFO 1")
                say(f'250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE="{cookie_path}"')
                say('250-VERSION Tor="0.4.9.15"')
                say("250 OK")
            elif word == "AUTHCHALLENGE":
                nonce, server = bytes.fromhex(cmd.split()[2]), secrets.token_bytes(32)
                message = cookie + nonce + server
                expect = hmac.new(C2S, message, hashlib.sha256).hexdigest()
                say(f"250 AUTHCHALLENGE SERVERHASH={hmac.new(S2C, message, hashlib.sha256).hexdigest()} SERVERNONCE={server.hex()}")
            elif word == "AUTHENTICATE":
                if cmd.split()[1] != expect:
                    say("515 Authentication failed: Safe cookie response did not match expected value.")
                    writer.close()
                    return
                say("250 OK")
            elif word == "TAKEOWNERSHIP":
                owned = True
                say("250 OK")
            elif word in ("SETEVENTS", "DEL_ONION", "ONION_CLIENT_AUTH_ADD", "ONION_CLIENT_AUTH_REMOVE", "SIGNAL"):
                say("250 OK")
            elif cmd == "GETINFO status/bootstrap-phase":
                say('250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=50 TAG=loading_descriptors SUMMARY="Loading relay descriptors"')
                say("250 OK")
                await writer.drain()
                await asyncio.sleep(0.2)
                say('650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"')
            elif word == "ADD_ONION":
                address = os.environ["FAKE_TOR_ADDRESS"]
                say(f"250-ServiceID={address}")
                say("250 OK")
                await writer.drain()
                await asyncio.sleep(0.1)
                say(f"650 HS_DESC UPLOADED {address} UNKNOWN $AAAA~relay ABCD")
            else:
                say(f'510 Unrecognized command "{word}"')
            await writer.drain()
        if owned and not gone.done():
            gone.set_result(True)                   # TAKEOWNERSHIP: tor exits when its owner goes

    await asyncio.start_unix_server(client, path=control)
    await gone


asyncio.run(main())
