# DA Vibe Manager manual

This is the full guide. For what DA Vibe Manager is and how to install it, see the
[README](README.md).

> **Beta.** DA Vibe Manager is beta software: expect rough edges, and use it at your own risk.

## Contents

- [First start](#first-start)
- [Chats](#chats)
- [What it hands over](#what-it-hands-over)
- [How deep a change goes](#how-deep-a-change-goes)
- [What it costs](#what-it-costs)
- [Which host runs the model](#which-host-runs-the-model)
- [Keeping your apps up to date](#keeping-your-apps-up-to-date)
- [Starting an app again, cleanly](#starting-an-app-again-cleanly)
- [Sharing an app](#sharing-an-app)
- [Backups](#backups)
- [How it stays safe](#how-it-stays-safe)
- [Running from source](#running-from-source)
- [Coming from DA Linux Agent](#coming-from-da-linux-agent)

## First start

DA Vibe Manager lives in your system tray, with a small window for its chats. If Podman isn't
installed yet, the first screen says so and offers **Install Podman**: the app's own install
command for your distribution, shown in full, run as administrator once you enter your password
in your desktop's prompt (the app never sees it). You can also copy the command into a terminal.

Paste your NanoGPT API key on the first screen and that's it: the key goes to your system's
keyring (GNOME Keyring or KWallet), never into a file or the sandbox. The first start prepares
the sandbox, which takes a few minutes. In Settings you can choose to have it start with your
computer. With 4 GB of memory, set the sandbox to 2 GB and 2 CPUs (Settings → The sandbox).

The window uses your system's WebKitGTK. Without it, or with no graphical display, DA Vibe Manager
opens in your web browser instead and says what to install.

## Chats

Each chat starts with a choice, and keeps to it:

- **Help me fix or add a feature to an app**: pick one of your apps, or name one you use, and say
  how it should be better. The chat is about that app only, and everything it builds goes on it.
  **Improve this app** in My apps starts one too.
- **Get an app working on this computer**: an app it built doesn't start, crashes or looks wrong
  here, though it worked in the sandbox or on someone else's computer. Pick the app, say what you
  see, and the assistant looks into it on your computer, asking before every command: it runs the
  app and reads what it prints, and checks for what AppImages commonly trip on (FUSE, missing
  libraries, an older system library, graphics, Wayland). Nothing is built in this chat. When it
  knows why, it shows **What I found**, and **Fix the app's build with this** opens the app's own
  chat with it (you can change it first), where the build is fixed so the app works here and still
  works where it did. It helps with other problems on your computer too. **It doesn't work on this
  computer** in My apps starts one.

You can attach files and pictures to a message (📎, or drop them on the window): detailed
instructions, or a picture of how something should look. Pictures go without their hidden details
(where and when they were taken). While it builds, you can keep talking with it.

Here's how a build goes:

> *(Help me fix or add a feature to an app → "gThumb")*
>
> **You:** I really like using gThumb for my images, but I hate that I can't click and drag to
> zoom like in ACDSee.
>
> **It:** gThumb is open source, so I can probably add that for you. First, let me check which version
> you have. *(a card: "Check which version of gThumb you have", the command, **Run it** /
> **Don't run**)*
>
> **It:** You have 3.12.6. *(a card: Build "Drag a box to zoom" into gThumb?, with what it costs:
> **Yes, build it** / **First, tell me how big a change it is** / **No thanks**)*
>
> **It:** I've read gThumb's viewer code: it's a significant modification, a new tool in the
> image viewer, about four files. *(the card again, with the size: **Yes, build it** / **No thanks**)*
>
> … *Working in its sandbox · 37 steps · Now: ran ninja -C build · for 3 min · Busy compiling
> (cc1 ×4) · processor 98%* …
>
> **It:** Here it is, running: *(screenshot)* *(📦 gThumb 3.12.6-dvm1, **Try it first**,
> **Install**, and **What changed?**)*
>
> *A month later, from the tray:* **gThumb 3.12.7 is out. It includes security fixes.** *(In My
> apps: a summary of what's new, **What's new?** for the project's own change log, **Build 3.12.7
> with my changes**, or **Skip this version**.)* The app puts your changes into the new release
> and builds it by itself, from the saved patches and build script, one change at a time; only a
> change that no longer fits goes to the assistant, and the others are done already. Installing
> it replaces your gThumb in place, and **Go back** returns to the one before.

## What it hands over

- **An app**: an AppImage the app builds itself from the committed source, in a clean container,
  to check the build works without anything done by hand. It's installed where your apps live:
  Gear Lever, or Shelly on Arch-based systems such as CachyOS, or else an entry in your apps menu.
  It sits next to your distribution's own copy, never over it. One app holds all your changes to it.
- **An add-on** for an app that loads them (an mpv script, a GIMP plug-in), copied into that
  app's folder. Never into a place that runs things at login or holds secrets, and a file of
  yours with the same name is kept.
- **Source code** with build notes, when an AppImage isn't practical.

Every build says what was tested in the sandbox and, just as plainly, what wasn't (your desktop
and theme, your other apps, real use), with a short checklist. **Try it first** runs it once
without installing it, and **It works** / **Something's wrong** tells the assistant how it went.

## How deep a change goes

Almost anything can be changed, but the more deeply something is woven into your system, the
more problems a change can cause. Changing an ordinary app you open yourself (an image viewer, a
media player) is the easy case: the changed copy runs next to yours. Part of the desktop itself
(the file manager, the panel, settings) is possible, but other parts of the desktop keep using
the original, extras may not work, and every update needs a rebuild: the assistant says so
before it offers, and suggests a setting, an add-on or asking the project first, and such builds
come with a warning. Below the desktop (drivers, system services), it doesn't build at all.

## What it costs

Answering questions costs little, but building an app takes the AI many steps: on a model paid
per use, like Claude Opus, a simple fix can cost a few dollars and a big change $50 or more, and
nobody can tell which it is until the AI has read the app's code. So before a build, you can ask
it to find out first whether it's a simple fix, a significant modification or a major rewrite
(it reads the code, without building anything). Set a spending limit on your API key at
nano-gpt.com.

The status line shows about what the open chat has cost so far: the tokens it used, at
NanoGPT's listed prices (models a NanoGPT subscription includes count as $0; hover over it to see
what they'd cost without one).

The assistant is Claude Code, on a NanoGPT model: GLM 5.3 by default (included in a NanoGPT
subscription), or private GLM 5.3, Claude Opus 5.5 or any other in Settings.

## Which host runs the model

NanoGPT runs an open model like GLM 5.3 on whichever of its many hosts it chooses. On a
subscription that's included, but it can be slow. **Settings → The assistant → Host for GLM 5.3**
lets you choose instead, with NanoGPT's own figures for each host (precision, whether it keeps
your prompts, where it is, how soon it starts answering and how fast it writes, its price):

- the fastest overall (what NanoGPT calls `:fast`);
- the fastest to start answering;
- the fastest writing;
- the cheapest;
- or one host you know is reliable. If that host is down, NanoGPT uses another, rather than
  stopping the assistant mid-build.

Only hosts at FP8 or better are used unless you untick it: lower precision is quicker but makes
more mistakes. **Any choice but NanoGPT's own is paid per use, even with a subscription**, at
the host's price plus NanoGPT's small fee. The status line counts it as paid. When NanoGPT's
bill for a reply shows it ignored your choice (the host was down), the app tells you.
Private, TEE and Claude models run where they run, so they have no host to choose.

## Keeping your apps up to date

My apps shows each app's official source (GitHub, GitLab…), the release it's built on, and your
changes on top of it. While the sandbox runs, it asks each app's official repository (from
inside the sandbox) for new releases, every day, week or month, or only when you ask: each app
can choose. When one is out, it says so, with security fixes first.

Building the new version takes your computer's power for a while, so by default it's done at a
quiet time you set (3:00 AM unless you change it), not while you're using the computer, and
never on battery unless you allow it; an app can also build straight away, or only when you say
so. **Build it now** is always there. Installing the new build replaces the old one in place,
and **Go back to …** returns to the one before.

## Starting an app again, cleanly

An app built on a fork, or with code pulled in from other apps' histories, may no longer carry
its changes over by itself. **Start again, cleanly** in My apps has the assistant make it again:
the project's official release, with each of your changes made afresh on it (a fix of yours in
your own fork can be copied in as its commit). You confirm on a card that it takes the place of
the one you have; installing it then replaces that one where it is.

## Sharing an app

**Share…** on an app in My apps saves it as a `.vibe` file in your Downloads folder, to give to
someone else who uses DA Vibe Manager. It holds what makes the app: its official source and the
release it's built on, each of your changes with its notes and code, and how it's built. Not your
chats, your API key, your builds, or anything about your computer. It isn't locked: there's nothing
secret in it, and it's a plain zip whose README says how to apply the changes even without the app.

Before it saves the file, **Share…** shows you what goes in it: each change's title and notes,
which you can correct there. Anything in them that came from your computer (a name, a path, a
line of a command's output) is pointed out, so you can take it out first. The assistant writes the
notes for whoever you share with, and keeps them up to date: a build that changes one of your
changes comes with new notes for it, and it can correct notes without building anything.

**Export AppImage** on an app in My apps saves the app itself (the build you have installed, or
the newest) to your Downloads folder, to run on another computer or keep: it runs by itself on
systems as new as Ubuntu 24.04 or Mint 22, with nothing to install. That copy isn't kept up to
date, so for someone who uses DA Vibe Manager, **Share…** is better.

**Import an app…** in My apps reads one strictly, then shows where it comes from (check that it's
the project's official source, not a copy), each change with its exact code, and how it's built.
Meanwhile a reviewer outside the sandbox reads the changes and build script: whether they do what
their notes say and nothing more, and whether they send anything anywhere, touch your files, or
download and run things. You then import it as an app of its own (with its own name, next to any
you have), or add its changes to your own copy of that app. Either way it's only built when you
click **Build it**: from the official source with the changes, in the sandbox. Nobody's built app
is ever passed along. After that it's yours, kept up to date with the project's releases like your
other apps.

**Versions, across computers.** A shared app knows who it is wherever it goes, and which systems
each version is known to work on (from **It works**, or **It works here** in My apps). Say you made
gThumb on Ubuntu and shared it, and Sam imported it on Arch, where it wouldn't start. Sam got it
working (**It doesn't work on this computer**, then the fix in gThumb's chat), so Sam's version now
works on Arch and Ubuntu, and yours still only on Ubuntu:

- Sam's card in My apps suggests **Share this version** back, and says why: your copy doesn't have
  the fix, so anyone using it on Arch would hit the same problem.
- When you import Sam's file, the app sees it says it's a newer version of your gThumb, says what's
  newer (here, how it's built) and where it's known to work, and offers **Update your gThumb to this
  version**. A file's word about its version can't be checked (anyone with your earlier file could
  make one that says it's newer), so it's never chosen for you: take it when you know who sent it.
  Changes only you have stay. It's built again on your release, and the gThumb you have stays
  installed until you install the new build.
- An older file than yours says so (keep yours, and share yours if they need it). One where you've
  both changed things since says that too, and suggests importing it as an app of its own first.

## Backups

Your apps exist only here: their changes, notes and build steps, and the builds you installed. A
backup holds all of it, so you can restore it on this computer or a new one and carry on: your
apps with their changes, the installed version of each (ready to install again without
building), your chats, settings and API key. It doesn't need the sandbox's own files: each app's
source is fetched again from its official project.

Backups are locked with a password you choose (scrypt and AES-256-GCM): nobody can open one
without it, so keep it safe. **Settings → Backups** makes one now, restores one, and can make
them by itself every day, every week or after each new app or change, into a folder you choose
(a USB drive, or a folder your cloud storage keeps), keeping the newest few. On a new computer,
the first screen has **Restore a backup**. Restoring moves what was there aside instead of
deleting it, and keeps the new computer's own settings (where apps are installed, the sandbox's
size).

## How it stays safe

The assistant runs **inside a sealed Podman container on your computer, not on your computer
itself.**

- **In its sandbox, it's free.** It can download source code, install tools, build and test
  apps (GUI apps too, on a virtual screen) and take screenshots to show you.
- **On your computer, it can do nothing by itself, and it sees nothing.** The container has no
  access to your files, no Linux capabilities and no network of its own.
  - When it needs to look at something here, it shows you a card: what it wants to find out,
    in plain words, and the exact command.
  - Nothing runs until you click **Run it**. Administrator commands go through your desktop's
    own password prompt, and **Stop** stops them too.
  - What a command printed is shown to you first, with passwords and keys blanked out. You
    send it or keep it private. (Settings can switch this to automatic. Anything that looks
    private still waits for you.)
- **A second opinion.** A separate AI, outside the sandbox, reads commands that change things
  before you run them. By default it's GLM 5.3 too; a private (end-to-end encrypted) model is a
  choice in Settings. It doesn't review the apps the assistant builds: a whole app is far more
  code than it can read, so it could only ever say it wasn't sure. **What changed?** on each
  build shows you the exact change against the official source instead.
- **Its way out is narrow and visible.** The sandbox reaches the internet through this app:
  - HTTPS to public sites only, never your home network or this computer (not even through its
    public IPv6 address), and never plain http;
  - its model requests go out with your key only as the assistant's messages: none of your
    provider's other paid services;
  - every connection is listed under **☰ → Sandbox activity**;
  - your API key stays in your keyring. The app adds it to the assistant's requests on the
    way out, so the sandbox never holds it.
- **It knows only what you choose to share.** Settings can tell it about your system and
  hardware in every chat (shown exactly, read by this app; off until you turn it on), so it
  needn't ask each time.
- **What you send it is what it has.** Its sandbox can reach public websites (it has to, to
  download source code and tools), and what a program there sends over HTTPS can't be seen from
  outside it. So treat anything you send the assistant (a command's output, a file you attach)
  as something that could leave your computer: that's why output waits for you to read it
  first, with passwords and keys blanked out.
- **It searches the web, but not with anything from your computer.** To learn how to do
  something, or to find out whether someone has already built what you want (a fork, a patch,
  a plug-in), it searches through NanoGPT: Perplexity to gather information, Kagi to find
  official sites. The app runs every search, and checks it in code first. A search, a web
  address it reads, or a site name it connects to that holds something you sent from your
  computer is refused: a version, a file, network or computer name, an address, your login, or
  a line copied from a command's output. This keeps its own searching clean; it can't stop a
  program in the sandbox from sending on what you gave it.
- **Your apps stay on the official code.** An app is always the project's own release with your
  changes on top, nothing else: never someone's fork, nor another app's code in the sandbox as a
  base (code it borrows from them becomes part of your change, and its notes say where it came
  from). The app checks this against the project's own repository whenever something is
  delivered, and keeps its own copy of that repository, which the assistant can read but not
  change. That's what lets it carry your changes over to new releases by itself.
- **What you read is what's built.** The app takes its own copy of each delivered commit into a
  clean container, where nothing of the assistant's runs, before it checks anything: **What
  changed?**, the checks and the build are all of that copy, so nothing left running in the
  sandbox can change one after another. Updates the app makes by itself happen there too, from
  your changes and build script as the app keeps them.
- **Apps it builds are yours to inspect.** Each comes with the exact change against the
  official source, notes on what was asked and how it was done (so it can be done again on
  the next version), and a checksum. Nothing starts until you click **Try it first** or
  **Open it**.
- **Add-ons stay out of harm's way.** An add-on is never installed where things run by
  themselves (at login, in every shell, on D-Bus), on your PATH, where keys, passwords or browser
  profiles are, or into Podman's own settings.

## Running from source

With Python 3.11 or newer:

```bash
sudo apt install podman python3-venv python3-gi gir1.2-webkit2-4.1 gir1.2-ayatanaappindicator3-0.1
git clone https://github.com/DigitalArchon/DAVibeManager.git && cd DAVibeManager
python3 -m venv --system-site-packages .venv   # system-site-packages gives access to GTK/WebKit
.venv/bin/pip install -e ".[dev]"
.venv/bin/davibemanager            # --hidden starts it in the tray, --browser in your web browser
```

The tests:

```bash
.venv/bin/python -m pytest              # unit tests
.venv/bin/python -m pytest -m podman -s # end to end: the real Claude Code in the real sandbox, a fake model
```

The Podman test checks the isolation from inside the container. It then has the real CLI ask
for a command, and checks that the command doesn't run until it's approved and that the model
receives only the output the user sent.

How the AppImage is built, and how to check a release is exactly what its source makes, is in
[packaging/README.md](packaging/README.md).

## Coming from DA Linux Agent

DA Vibe Manager used to be called DA Linux Agent. Its first start moves your settings, API key,
apps, chats and sandbox over by itself (quit DA Linux Agent first). Apps it built before keep
their "(DLA)" names, so their updates replace them rather than adding a second copy.
