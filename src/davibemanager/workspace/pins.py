"""Everything the workspace image is built from, pinned. Change these deliberately: a new value
means a different image (its tag is a hash of these, the Containerfile and the entry script)."""

# Ubuntu 24.04 base image, by digest (the same one DA Toolkit's AppImage is built on)
BASE_IMAGE = "docker.io/library/ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3"
# the image's own packages come from the Ubuntu archive as it was at this moment
APT_SNAPSHOT = "20260930T000000Z"

# appimagetool 1.9.1 (AppImage/appimagetool releases; digest as GitHub lists it)
APPIMAGETOOL_URL = "https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-x86_64.AppImage"
APPIMAGETOOL_SHA256 = "ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0"
# AppImage type 2 runtime, static (no libfuse2 needed where the AppImage runs)
RUNTIME_URL = "https://github.com/AppImage/type2-runtime/releases/download/20251108/runtime-x86_64"
RUNTIME_SHA256 = "2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d"

# The Claude Code CLI bundled in claude-agent-sdk 0.2.164 (CLI 2.1.292). The image takes the
# binary from the installed SDK, so the CLI in the container always speaks the SDK's protocol;
# this hash makes an SDK upgrade a deliberate change here too.
CLAUDE_CLI_VERSION = "2.1.292"
CLAUDE_SHA256 = "a967e7b1d8b4e47ee421d5433027880347952b0c0857abf880e2c942a4ec93b3"
