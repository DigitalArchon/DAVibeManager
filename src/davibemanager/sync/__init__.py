"""The user's apps, the same on each of their computers: synced directly between them over Tor.

No server and no account: each computer the user pairs runs an onion service of its own (the
app's own tor, `tor.py`), which only the computers paired with it can find (Tor's client
authorization: without the key, its descriptor can't even be read). Whenever two of them are on,
they sync, each fetching what the other changed.

What is synced is each app as `share.py` makes it for someone else: its official source and
release, each change with its notes, patch and revision history, the build script, and the
systems a version is known to work on. Not what belongs to one computer: what's installed there,
its builds, the sandbox, the chats, the API key. An app that arrives is built on each computer by
the app itself, as a shared one is, and installed there only when the user says so.

- `onion.py`: the onion services' keys and addresses, and the client keys.
- `pairing.py`: pairing two computers, with a code typed on one and six digits checked on both.
- `wire.py`: the messages two computers send each other, and how each proves which it is.
- `tor.py`: the app's own tor, and its control protocol.
- `store.py`: what sync keeps on this computer: its identity, the computers paired with it, and
  for each, the apps as they were when the two last agreed.
- `library.py`: the apps as sync sees them, and how a change on either side is merged.
- `service.py`: all of it together, for the engine.
"""
