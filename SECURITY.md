# Security policy

## Reporting a vulnerability

Please email **jason@digitalarchon.com.au** with the details and, if you can, steps to
reproduce. Don't open a public issue or pull request for a vulnerability.

You'll get a reply as soon as I can manage. This is a one-person project with no bug bounty,
but reports are taken seriously and credited in the fix unless you'd rather not be named.

## Supported versions

DA Vibe Manager is in beta. Only the latest release (or `main`) gets fixes.

## What's in scope

Anything that breaks one of DA Vibe Manager's promises, as
[docs/security-and-privacy.md](docs/security-and-privacy.md) sets them out, for example:

- the AI (or text in a command's output, a web page or a shared app) getting a command run on
  your computer without your click, or reaching your files from the sandbox;
- a way out of the sandbox: to this computer, your home network, or past the gateway's
  HTTPS-only, public-only proxy;
- the API key reaching the sandbox, or being used for anything but the assistant's messages;
- a secret (an API key, the backups' password, a password written into an address) written in the
  clear to disk, a log or a message, or the window's token reaching anyone else logged in to the
  computer;
- anything sent to a TEE or private model whose attestation doesn't hold, or a TEE reply its check
  passes that isn't its attested enclave's;
- output reaching the AI without being shown to you first (when that's the setting), or secrets
  surviving redaction;
- something from your computer, or a key or password, getting into a web search the app runs for
  the assistant or a web address it lets it read, or text aimed at the assistant in search
  results reaching it unmarked;
- a delivered or imported app built from anything but the official source with its recorded
  changes, or what **What changed?** shows differing from what was built;
- an add-on installed somewhere that runs things by itself or holds secrets;
- a crafted `.vibe` file or backup doing more than it should when opened;
- sync: a computer that isn't one of your group reaching one of yours or reading what they send
  each other, joining without a code you showed, staying in after it was removed, or an app
  arriving by sync doing more than the same app shared as a file could;
- bypassing the local server's token, or a model reply that makes the window load remote
  resources or run script.

Weaknesses in upstream projects (Podman, Claude Code, NanoGPT, WebKitGTK, Tor and so on) should go to
those projects, though a heads-up is welcome if DA Vibe Manager can mitigate them.
