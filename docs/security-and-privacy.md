# Security and privacy

How DA Vibe Manager handles your security and privacy: what leaves your computer and who gets it,
what is checked and how, what is kept on your computer, and what the app can't protect you from.
It describes the app as it is now (November 2026). The [manual](../MANUAL.md) says how to use each
part; this says what each part does, and what it doesn't. To report a vulnerability, see
[SECURITY.md](../SECURITY.md).

## Contents

- [In short](#in-short)
- [Who the app talks to](#who-the-app-talks-to)
- [The network rules](#the-network-rules)
- [Keys and passwords](#keys-and-passwords)
- [The AI models](#the-ai-models)
  - [Ordinary models](#ordinary-models)
  - [Private models](#private-models)
  - [TEE models](#tee-models)
- [The sandbox](#the-sandbox)
- [Commands on your computer](#commands-on-your-computer)
- [Web searches and the pages the assistant reads](#web-searches-and-the-pages-the-assistant-reads)
- [The Claude Code gateway](#the-claude-code-gateway)
- [Your apps' code](#your-apps-code)
- [Sync between your computers](#sync-between-your-computers)
- [The window](#the-window)
- [What is kept on this computer](#what-is-kept-on-this-computer)
- [What the app can't protect you from](#what-the-app-cant-protect-you-from)
- [Reporting a vulnerability](#reporting-a-vulnerability)

## In short

**What leaves your computer:**

- **What you give the assistant**: your messages, the files and pictures you attach, and the output
  of the commands you choose to send it. With everything the assistant does in its sandbox, it goes
  to NanoGPT, and from NanoGPT to the company that runs the model you chose. They can read it,
  unless you choose a private model, which is end-to-end encrypted.
- **What the assistant fetches**: source code, tools and web pages, from public websites, over HTTPS
  only, and its web searches, through NanoGPT to a search provider.
- **The app's checks of a TEE or private model**, before anything is sent to one: to NanoGPT, Intel,
  NVIDIA, Sigstore and Tinfoil, and to RedPill only if you turn that on.
- **Sync** between your own computers, through Tor, end to end.

**What never does:**

- **Your files.** The assistant can't read them. What a command prints on your computer is shown to
  you first, and goes to the assistant only when you send it (unless you choose to send it
  automatically, and then not when anything in it looks private).
- **Your API key**, except to NanoGPT with your requests. It never reaches the sandbox or a log, nor
  any file but a backup, which is locked with your backup password.
- **Your backup password**: it stays in your keyring. A password written into an address goes only
  to that address, and into no file but a backup.
- **Anything from your computer in a web search**, or in a web address the assistant reads: the app
  refuses such a search or address in code.
- **Your chats, settings and API key**, by sync: only your apps are synced.

## Who the app talks to

Every connection the app makes, and why. **☰ → Sandbox activity** lists, as they happen, the
sandbox's connections and the app's own requests to a model (second opinions, update summaries,
reviews, pictures described). The connections that check a model's attestation and each reply's
record, below, aren't listed there: what each reply's check found shows as its mark.

### NanoGPT (nano-gpt.com)

Your AI provider, always over HTTPS. With your API key, the app sends it:

- the assistant's requests to its model, from the sandbox through the app's gateway
  ([below](#the-claude-code-gateway));
- the app's own requests to a model: a second opinion on a command, the summary of what's new in an
  update of one of your apps, the review of an app you import, and a picture described for the
  assistant when its own model can't see pictures;
- the assistant's web searches ([below](#web-searches-and-the-pages-the-assistant-reads));
- the request for its list of models, with their prices and what each can do;
- for a TEE model: the request for its attestation, and after each reply, for the record NanoGPT
  keeps of it ([TEE models](#tee-models));
- for a private model: the Private Mode check before each request, and the sealed request itself
  ([Private models](#private-models)).

Without a key: the list of hosts that run an open model (when you open its host choice in Settings),
the list of Private Mode models, and a private model's attestation, which comes through NanoGPT's
relay.

NanoGPT can read everything sent to an ordinary or a TEE model. Of a private model's requests it
sees your account, the model, when, how much and what it costs: the request itself is sealed on
this computer for the model's enclave.

### The companies that run the models

NanoGPT passes each request on to whoever runs the model: Anthropic for a Claude model; one of many
hosts for an open model such as GLM 5.3, NanoGPT's choice unless you choose one (manual: [Which host
runs the model](../MANUAL.md#which-host-runs-the-model)); the TEE provider for a TEE model; Tinfoil's
enclave for a private model. The app never talks to them itself. Each reads what it is sent, except
a private model's, which only the attested enclave can open.

### Intel (api.trustedservices.intel.com, certificates.trustedservices.intel.com)

When a TEE model is attested: Intel's public certificates, revocation lists and ratings of the
platform's firmware, to check the enclave's quote up to Intel's root. The request names the platform
family the quote is from; nothing of yours goes, and no key. A private model's enclave on Intel
hardware is checked against the same service.

### NVIDIA (nras.attestation.nvidia.com)

When a TEE model is attested: the GPU evidence in that model's attestation, with the app's fresh
number, goes to NVIDIA's attestation service, and its signed verdict is checked with the keys NVIDIA
publishes there. Nothing of yours goes, and no key.

### Tinfoil, Sigstore and GitHub (private models)

When a private model's enclave is attested (before its first request, and before a request once
that attestation is five minutes old), Tinfoil's own software checks the attestation that comes
through NanoGPT's relay. For that it fetches Sigstore's public trust root (tuf-repo-cdn.sigstore.dev),
Tinfoil's latest router release, and for an Intel TDX enclave its published hardware measurements,
from Tinfoil's proxy of GitHub (github-proxy.tinfoil.sh), and, where the attestation doesn't carry
it, AMD's certificate for the processor through Tinfoil's proxy (kds-proxy.tinfoil.sh). These are
public records: nothing of yours goes, and no key. The app makes Tinfoil's fetches follow a redirect
only to HTTPS, and never from the internet into this computer or your network. Sigstore's trust root
is fetched by Sigstore's own library, by its own rules; what it fetches is signed, and checked.

### RedPill (api.redpill.ai): only with Name the provider behind each TEE reply

Off unless you turn it on (**Settings → TEE models**). With it on, after a TEE reply whose signed
receipt holds, the app fetches RedPill's public record of the session that served it, to name the
provider that ran the model ([below](#naming-the-provider-behind-a-reply)). The request is the
session's id in the record's address, and nothing else: no key, none of your messages. RedPill then
sees your computer's internet address, and that one of its models was used around then. Each
session's record is fetched once while the app runs, and never for a model Chutes serves. It goes
over HTTPS, through your system's proxy if it has one, by the same rules as the app's other checks.

### Search providers (through NanoGPT)

The app never talks to a search provider itself: NanoGPT passes each search on, to Perplexity and
Kagi by default, to Linkup alone with **Keep nothing**, to Valyu when the chosen one fails on
NanoGPT's side, or to another you choose. The provider reads the query; what it keeps is its own
policy, except Linkup's, which keeps nothing.

### Ubuntu, Docker Hub and GitHub (preparing the sandbox)

When the sandbox's image is made (at the first start, after **Remove the sandbox…**, or when an
update of the app changes what the sandbox is made from), Podman fetches the pinned Ubuntu 24.04
image from Docker Hub (docker.io), by its exact digest. Its packages come from Ubuntu's snapshot
server (snapshot.ubuntu.com), the archive as it was on one date, or, only if you choose it for when
that server is unavailable, Ubuntu's live archive or your own mirror. apt checks every package against
Ubuntu's signing key. The two AppImage tools the sandbox builds apps with come from GitHub, each
checked against its pinned checksum. Claude Code isn't downloaded: it is the copy that comes with
the app, checked against its checksum.

### The sandbox's own connections

The assistant fetches what it needs from public websites: an app's source code from its official
project (GitHub, GitLab and so on), the project's releases, tools, packages from Ubuntu's archive,
documentation. All of it goes through the app's proxy, over HTTPS, to public addresses only, and each
connection is listed in **☰ → Sandbox activity** ([The sandbox](#the-sandbox)). Claude Code's own
updates, telemetry and error reports are turned off in the sandbox.

### Tor (sync)

Only while sync is in use: the app's own copy of tor connects to the Tor network, through which
your computers reach each other ([Sync](#sync-between-your-computers)). Nobody on the Tor network
can read what they send each other, and only your computers can find this one.

### Your router, on your own network

Now and then the app asks your router (NAT-PMP, else UPnP) for this network's public address, so
that the sandbox can't reach your network through it ([The sandbox](#the-sandbox)). Only this
network's router is asked, at a local address; nothing goes out to the internet.

### Your distribution's package servers (installing Podman)

Only when you click **Install Podman**, or ask to uninstall it: the command is shown in full, and
runs as administrator once you enter your password in your desktop's prompt. Your package manager
then fetches from your distribution's own servers, as it always does.

## The network rules

- **HTTPS only.** Every address the app sends anything to is HTTPS, except an address on this
  computer or your local network: localhost, the loopback and private ranges (10.0.0.0/8,
  172.16.0.0/12, 192.168.0.0/16, fc00::/7), link-local addresses and `.local` names, where plain
  `http://` is allowed (for a model server of your own, say). An address that is neither is
  refused, saying why: it is never used, and never quietly rewritten.
- **Redirects.** A model provider's redirect is never followed: the request, your words in it,
  would go wherever it points. Nor is one in a TEE model's checks; Tinfoil's checks of a private
  model follow one only to HTTPS, and never from a server on the internet into this computer or your
  network.
- **Proxies.** The app has no proxy setting of its own: its requests use your system's proxy
  settings (`HTTPS_PROXY` and the like), as most programs do. Sync goes through Tor.
- **The sandbox** reaches nothing but public internet addresses, over HTTPS, through the app
  ([below](#the-sandbox)).
- **Links in a reply.** A link that isn't secure (plain `http://` to anywhere but this computer or
  your network) is marked **⚠ not secure**, and opening it asks first, naming the whole address.

## Keys and passwords

- **Your API key** is kept in your system's keyring (GNOME Keyring or KWallet), never in a file.
  Without a secure keyring the app keeps no key at all, rather than one in a plain file, and says
  what to install. Once read it is kept in memory while the app runs, so that a keyring that locks
  itself again doesn't stop the assistant. It goes only to your provider, NanoGPT, with your
  requests: the sandbox never holds it (the gateway adds it on the way out), and it isn't in any
  log, message or error. A key with a space, a line break or a character no key has in it is
  refused before anything is sent, without being repeated back.
- **A password written into an address** (`https://user:password@host/…`, a provider's or a
  package mirror's) goes to your keyring with the address as typed; the settings file has the
  address without it. It goes only to the address it was typed for, and wherever an address is
  shown or logged, the user name and password are left out.
- **Your backup password**, when backups are made automatically, is kept in your keyring too.
  Backups are locked with it (scrypt and AES-256-GCM); they hold your API key, so keep the password
  safe.
- **Sync's keys** (this computer's own, and your group's secret) are in files only you can read,
  in the app's settings folder ([below](#what-is-kept-on-this-computer)). They are never in a backup.

The app doesn't warn before a key would go over plain `http://` to another machine on your
network: Settings only sets up NanoGPT, over HTTPS, and a server of your own on your network has to
be added by hand. Anyone on that network could read a key sent to it that way.

## The AI models

Which model reads what you send depends on the model you choose (manual: [What it
costs](../MANUAL.md#what-it-costs)). The assistant's model, its model for quick tasks, the model that
describes pictures to it and the reviewer for second opinions are each one of these three kinds.

### Ordinary models

GLM 5.3 (the default), Claude Opus 5.5, and any other model NanoGPT offers. What you send goes over
HTTPS to NanoGPT, which reads it and passes it on to the company that runs the model, which reads it
too. What each keeps is up to its own policy. A model on a server of your own, on this computer or
your network, gets it directly (over plain `http://` if that is the server's address), and nobody
else does.

### Private models

NanoGPT's `private/` models (such as Private GLM 5.3) run in Tinfoil's enclaves, and are end-to-end
encrypted:

- **Attested before anything is sent.** Before a private model's first request, and before any
  request once the last attestation is five minutes old, the app checks the enclave's attestation:
  against AMD's or Intel's roots for its hardware, and against Sigstore's public record of the
  release of Tinfoil's software it runs. One that doesn't hold refuses the request: nothing is sent,
  not even NanoGPT's charge for it. The app says when the enclave runs an older release than the
  latest (it is still verified).
- **Sealed on this computer.** Each request is sealed to the key that attestation proved only the
  enclave holds, and the reply comes back sealed the same way. NanoGPT relays what it can't read:
  it sees your account, the model, when, how much and what it costs.
- **Sealed, or not at all.** A private model is never sent anything any other way: a reply that
  isn't sealed, or that doesn't come back through Private Mode, is refused, and nothing falls back
  to a plain request. A model NanoGPT no longer offers is refused before anything is sent.
- **The whole chat.** With a private assistant, everything of the chat goes sealed, or not at all:
  its quick tasks, the pictures described to it (by private DeepSeek V4.1 Flash) and second opinions
  on the commands it proposes (the reviewer must be private too). A chat that ran on a private model
  can't be carried on with one in the clear: all of it would go along.
- **The prompt cache** is the app's own: the key to it is made on this computer, sealed with each
  request, and kept in memory only, so nobody else, NanoGPT included, can probe it.

### TEE models

NanoGPT's `TEE/` models run in a trusted execution environment, but aren't end-to-end encrypted:
what you send them passes NanoGPT's servers in the clear. What the app checks:

**Before anything is sent**, and again before a request once the attestation is 15 minutes old (on a
clock that counts while the computer sleeps), the app asks for the enclave's attestation, with a
fresh random number of its own, and checks:

- that the Intel TDX quote, read from its own signed bytes, binds the enclave's signing key to that
  number; where NanoGPT has it, RedPill's gateway's own report too, for another fresh number, whose
  quote binds all the gateway's keys, those that sign each reply's record and its receipts;
- that each quote verifies up to Intel's root, isn't revoked or a debug enclave, and what Intel says
  of the platform's firmware;
- that NVIDIA's signed verdict on the GPUs is for the app's number, and passes.

Anything forged, revoked or made for another number is refused, and nothing is sent. What couldn't
be checked, or isn't current, makes the attestation **partial**: the request still goes, and the app
says so once for each model, naming each shortfall, with what was attested:

- **RedPill's TEE gateway**, for most of NanoGPT's TEE models: "TEE gateway attested". The gateway
  passes each request on to the machine that runs the model (in November 2026 Phala's, Fortanix's,
  NEAR AI's, 0G's, Tinfoil's router or Chutes'). The app doesn't attest that machine: that it is a
  verified TEE is the gateway's word, in each reply's signed receipt ("the model's own enclave
  unchecked"). The GPU evidence in NanoGPT's report is made for the app's number, but the gateway's
  quote doesn't commit to it, so the GPUs may be another machine's ("GPUs not tied to the quote").
  A model whose own attestation can't be had for the app's number is attested through the gateway
  alone, with "no GPU evidence" too.
- **Each instance**, for a model Chutes serves itself: each instance's quote binds its own key and
  GPU evidence. Chutes signs no replies, so nothing shows which instance answered: NanoGPT routes
  each request, and a model may be served elsewhere when its provider is busy. Where RedPill's
  gateway answers some of these models' requests instead, it is attested too.

A model offering no attestation the app can check for its own number (the Tinfoil-hosted TEE
models) is refused. The app has no setting that refuses a partial attestation: partial ones are sent
to, and said.

**After each reply**, once it has reached the assistant, the app fetches the record NanoGPT keeps of
it, signed by an attested key, and checks it against the exact bytes that came back; where the
gateway kept a signed receipt for the reply, that too: for the same exchange, saying the machine the
reply came from was verified, which is the gateway's word. Every reply of a TEE model is checked so,
the app's own requests' as well as the assistant's, and **☰ → Sandbox activity** marks each:

- **TEE verified**: the attested key signed this reply's record, for the exact text that came back,
  and its receipt (where read) holds.
- **TEE signed, text not compared**: signed by the attested key, but NanoGPT rebuilds this model's
  replies, so the text can't be compared with the record.
- **TEE ⚠ reply not verified**: no record of the reply could be read (Chutes keeps none, or the
  check couldn't be made), so nothing shows it came from the attested enclave. A model attested
  through the gateway alone has its own enclave only as the gateway's word, so a reply of it with no
  receipt that holds is marked so too.
- **TEE ⚠ check failed**: the reply doesn't match its record. The app says so, and attests the model
  again before anything more is sent to it.

Hovering over a mark says what it means, what in it is the gateway's word, and that what was sent
passed NanoGPT in the clear. The check never holds up or changes what the assistant, or you, are
given. Your own messages carry no mark: each of them leads to many requests of the assistant's, and
each of those is marked.

What a TEE attestation doesn't prove: which software the enclave runs (no measurement of it is
compared with a published one), what was sent (the record holds the request as NanoGPT forwarded
it), and, for a model RedPill serves, which machine ran the model. For a chat nobody else can read,
use a private model.

#### Naming the provider behind a reply

**Settings → TEE models → Name the provider behind each TEE reply** (off by default) shows who ran
the model beside the reply's mark: "TEE verified · run by Phala", say. Each receipt names the
gateway's session with the machine that answered by a hash of RedPill's public record of that
session, which says which provider it is. With the option on, after a reply whose receipt holds,
the app fetches that record from api.redpill.ai and believes it only if it is exactly the record the
receipt names, and the reply was served within the session's time. The cost to your privacy:

- it connects to api.redpill.ai directly, not through NanoGPT, so RedPill sees your computer's
  internet address and that one of its models was used around then;
- only the session's id is sent, never your messages or your key;
- a session's record is fetched once while the app runs (a session serves a provider for about an
  hour), and is a few kilobytes to a few hundred: one over 1 MB isn't read;
- it is never fetched for a model Chutes serves: each Chutes instance has a session of its own,
  megabytes each, and replies are spread across them.

What the record says is RedPill's word: the app doesn't check the machine it names. A record that
can't be fetched or believed names nobody, and the mark's tooltip says why; the reply's mark never
changes.

## The sandbox

The assistant (Claude Code) works in a container of its own, run by rootless Podman, as an ordinary
user of the container with no capabilities at all and no way to gain any. Nothing of your home
folder is in it: the only folder of this computer's it can reach holds the app's two gateway
sockets. A file you attach to a message is copied in. It has no network of its own; everything it
sends goes through the app:

- **The proxy** passes on only HTTPS (a `CONNECT` to port 443, and only TLS through it), and only to
  public internet addresses: never this computer, your network, or this network's public address on
  your router (where many routers serve their settings). The app resolves each name itself and
  connects to the address it checked, so an answer can't change under it. Plain http is refused,
  saying why. A host name holding something that came from your computer is refused too
  ([below](#web-searches-and-the-pages-the-assistant-reads)).
- **The model requests** go through the gateway ([below](#the-claude-code-gateway)).

Packages are installed into the sandbox by the app itself, as root inside the container only. What
the sandbox holds stays in Podman's storage, in volumes of its own, until you reset or remove it.

## Commands on your computer

The assistant can't run anything on your computer by itself. When it needs to look at something, it
shows a card: what it wants to find out, and the exact command.

- **Nothing runs until you click Run it.** You can change the command first, ask for a second
  opinion, or refuse. It runs with no input, for at most two minutes (you can change that, up to
  half an hour), and at most 2 MB of what it prints is read. A command as administrator goes through
  your desktop's own password prompt: the app never sees the password, and **Stop** stops it too.
- **Risk rules.** The assistant says how risky each command is; the app's own rules (in code) can
  only raise that, never lower it: deleting, formatting, changing packages or the system, rebooting,
  killing processes. A command that could interrupt what you're doing, lose data or lock you out
  asks once more before it runs.
- **Sensitive reads.** A command that would read or print a secret (password hashes, a private key,
  a `.env` file, a process's environment, `~/.ssh` or `~/.gnupg`), or that carries one in its own
  text, is flagged before it runs.
- **Its output waits for you.** What it printed is shown with passwords and keys blanked out, and
  goes to the assistant only when you send it, or not at all. With Settings set to send it
  automatically, anything that looks private still waits for you, and so does text aimed at the
  assistant, even text you can't see.
- **Second opinions.** A separate AI, outside the sandbox, reads commands that change things before
  you decide (Settings: every command, or only when you ask). It is GLM 5.3 unless you choose another;
  with a private assistant it must be private too.

## Web searches and the pages the assistant reads

The assistant may search the web on its own, through NanoGPT with your key, but only with what is in
its sandbox and your own words. The app runs every search, and checks it in code first: a search is
refused when it holds anything you sent the assistant from your computer (a version, a file,
network or computer name, an address, your login, five words in a row of a command's output), this
computer's identity, or anything that looks like a key, a token or a password, even one you typed
yourself. It is read as the search provider would read it, so characters no one can see can't hide
anything from the check. The same check is made on the address of every page the assistant reads,
and on the name of every site it connects to. What came from your computer is remembered for this
only as hashes ([below](#what-is-kept-on-this-computer)).

No search is end-to-end encrypted, even with a private assistant: NanoGPT and the search provider
read each one. **Settings → Web searches** chooses between the best results (Perplexity and Kagi, not
zero data retention) and **Keep nothing** (Linkup only, which keeps nothing, and no other provider
even when it fails). A private assistant starts with Keep nothing until you choose. Results are
untrusted: text in them that looks like instructions to the assistant is pointed out to it and to
you, and hidden text is taken out before it reads them.

The check keeps the assistant's own searching clean. It can't stop a program in the sandbox from
sending on what you gave it, over HTTPS, where the app can't see inside.

## The Claude Code gateway

The assistant's Claude Code reaches its model only through the app's gateway, a socket in the one
folder of this computer's that the sandbox can reach:

- **A token of its own.** Each request must carry a token made for that run of the gateway. The
  sandbox never holds your API key: the gateway adds it on the way out, read from your keyring.
- **Only the assistant's messages.** It passes on the requests Claude Code needs (its messages,
  counting their tokens, the model list), not your provider's other paid services, and only for the
  models you chose: a request for any other gets your quick-task model. With a private assistant,
  nothing of its chat goes to a model in the clear.
- **TEE and private models are checked first.** Every request goes through the same check the app's
  own requests do: a TEE model is attested before anything is sent to it (a model your provider's
  settings mark as TEE included), and a private model's requests are sealed, or refused.
- **Nothing followed, everything logged.** A redirect from the provider is never followed. Each
  request is logged with its model, sizes, status, timing and the tokens it used (which is what a
  chat's cost is worked out from), not what it said.

## Your apps' code

- **Always the official source.** An app is the project's own release with your changes on top,
  never someone's fork. The app checks each delivery against the project's own repository, and keeps
  its own copy of that repository, which the assistant can read but not change.
- **What you read is what's built.** Each delivered commit is copied into a clean container, where
  nothing of the assistant's runs, before anything is checked or built: **What changed?**, the checks
  and the build are all of that copy.
- **Shared apps are read strictly.** An imported `.vibe` file is checked field by field, and a
  reviewer reads its changes and build script before you choose to build it, from the official
  source, in the sandbox. A file's claim to be a newer version can't be checked, so it is never
  chosen for you.
- **Add-ons stay out of harm's way**: never where things run by themselves, on your PATH, or where
  keys, passwords or browser profiles are.

## Sync between your computers

Your computers sync your apps (each one's changes, notes, build steps, and which systems a version
works on) directly with each other, through Tor, with no server and no account:

- **Only your computers can find this one.** Each runs an onion service whose address leads nowhere
  for anyone without its key (Tor's client authorization), and each proves which computer it is
  before anything is sent. A computer you remove is shut out by all the others.
- **Joining takes a code you showed**: 16 digits, good once, then six numbers shown on both screens
  (and, if you choose, confirmed on both before the computer is added).
- **Nothing else is synced**: not your chats, settings, API key, builds or what's installed. An app
  that arrives is read as strictly as a shared one, built here from the official source, and
  installed only when you say so.
- **The app's own tor** runs only while sync needs it, with a folder of its own: it never reads your
  system's tor settings, nor touches a tor you run yourself.

## The window

The window talks to the app through a server on this computer that answers only requests carrying a
key made for this start. The key is never on a command line, where anyone else logged in could read
it: a browser is opened on a code that works once, for a couple of minutes, and only for you. The
folders the app runs and listens in are yours alone. A model's reply is shown with its formatting,
cleaned first: it can't make the window load anything (a picture, an embed) or run script, and its
links open in your browser.

## What is kept on this computer

- **Settings**: `~/.config/davibemanager/config.toml`, readable only by you. No key or password is
  in it.
- **Your chats, apps and builds**: `~/.local/share/davibemanager`, in folders only you can open: each
  chat's messages, the commands the assistant asked to run with what they printed (whether or not
  you sent it) and what you sent, the files you attached, and a log of what the app did (requests to
  models with their checks, attestations, refusals); your apps' changes, notes and build scripts;
  the builds the assistant delivered.
- **What was sent from this computer**, for the web-search check: only as hashes
  (`outside.json`).
- **Every connection** the sandbox and the app's requests to models made, as Sandbox activity lists
  them, and each TEE reply's check (`network.jsonl`).
- **Sync**: `~/.config/davibemanager/sync`, its keys and what it knows of your other computers, in
  files only you can read; tor's own data in `~/.local/state/davibemanager/tor`.
- **The sandbox**: in Podman's storage (`~/.local/share/containers`): its files, the tools it
  installed, and the assistant's own memory of each chat.
- **Your keyring**: your API key, a password written into an address, and your backup password when
  backups are made automatically.
- **Public records the attestation checks fetched**: Tinfoil's software and Sigstore's library keep
  them in their own cache folders (`~/.cache/tinfoil`, `~/.local/share/sigstore-python` and
  `~/.cache/sigstore-python`).

Kept only in memory, and gone when the app stops: your API key once read from the keyring, the
gateway's token, the window's key, attestations and their results, the private models' cache key,
and RedPill's session records.

A backup holds your apps, chats, settings and API key, locked with your backup password; it doesn't
hold sync's keys.

## What the app can't protect you from

- **What you send can leave your computer.** The sandbox can reach public websites (it must, to
  download source code and tools), and what a program in it sends over HTTPS can't be seen. Treat
  anything you send the assistant as something that could leave: that is why a command's output
  waits for you to read it first.
- **Your provider reads what isn't sealed.** NanoGPT, and the company running an ordinary or TEE
  model, read what is sent to it. Even a private model's requests show NanoGPT when, how much and
  what it costs.
- **A TEE attestation shows hardware, not software.** It shows genuine, current hardware holding a
  live key, bound to the app's fresh number; not which software that machine runs. For a model
  RedPill serves, the machine that runs the model is RedPill's word. (A private model's attestation
  checks its software too, against Tinfoil's signed release.)
- **Search providers keep what they keep.** Only Linkup keeps nothing.
- **A command you approve runs as you.** The app shows exactly what will run, with its risk and,
  if you ask, a second opinion: read each one before you click Run it.
- **Your computer itself.** Anyone, or anything, that already controls your account or your
  computer can read what the app keeps there.
- **Tor.** Someone watching your network can see that this computer uses Tor, though not what it
  sends.

## Reporting a vulnerability

Please report it privately, as [SECURITY.md](../SECURITY.md) says, not in a public issue. It lists
what is in scope.
