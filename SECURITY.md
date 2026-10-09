# Security policy

## Reporting a vulnerability

Please email **jason@digitalarchon.com.au** with the details and, if you can, steps to
reproduce. Don't open a public issue or pull request for a vulnerability.

You'll get a reply as soon as I can manage. This is a one-person project with no bug bounty,
but reports are taken seriously and credited in the fix unless you'd rather not be named.

## Supported versions

DA Vibe Manager is in beta. Only the latest release (or `main`) gets fixes.

## What's in scope

Anything that breaks one of DA Vibe Manager's promises, for example:

- the AI (or text in a command's output, a web page or a shared app) getting a command run on
  your computer without your click, or reaching your files from the sandbox;
- a way out of the sandbox: to this computer, your home network, or past the gateway's
  HTTPS-only, public-only proxy;
- the API key reaching the sandbox, or being used for anything but the assistant's messages;
- output reaching the AI without being shown to you first (when that's the setting), or secrets
  surviving redaction;
- something from your computer getting into a web search the app runs for the assistant;
- a delivered or imported app built from anything but the official source with its recorded
  changes, or what **What changed?** shows differing from what was built;
- an add-on installed somewhere that runs things by itself or holds secrets;
- a crafted `.vibe` file or backup doing more than it should when opened;
- bypassing the local server's token, or a model reply that makes the window load remote
  resources or run script.

Weaknesses in upstream projects (Podman, Claude Code, NanoGPT, WebKitGTK and so on) should go to
those projects, though a heads-up is welcome if DA Vibe Manager can mitigate them.
