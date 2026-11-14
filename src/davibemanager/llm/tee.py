"""TEE models on nano-gpt: attestation before anything is sent, and a signature check on
every reply. Ported from SealedLore (its providers/tee.py, Sept 2026); the checks are the same.
This copy is the one DA Vibe Manager's and DA Private Coder's llm/tee.py are, line for line but
their imports and names (each app's test_shared_code holds them to it): a change is made here
first, then copied.

What the attestation is of (looked into Nov 2026, in DA Vibe Manager): for most of nano-gpt's
TEE/ models it is RedPill's gateway (its "aci/1" report, relayed by nano-gpt), which passes each
request on to the model's host (Phala, NEAR AI, Tinfoil, Chutes...). Its quote is the gateway VM's;
the GPU evidence is the upstream node's, made with our nonce but not bound to the gateway's quote;
that the model itself runs in an enclave isn't in the report. So such an attestation is "partial"
here ("the model's own enclave unchecked"), and the top bar says so, a model attested through
the gateway alone too. For a model sealed end to end, use a private/ one (llm/private_mode.py).

Which machine was attested is said wherever an attestation is shown (`Attestation.attested`,
`what_was_attested`; from SealedLore 9af15c1, Nov 11 2026): "TEE gateway attested" for RedPill's
gateway, whose word the machine that runs the model is, in each reply's receipt; each instance for
Chutes, which signs no replies; else the one enclave whose key signs them. The GPU evidence
nano-gpt's report carries is for our nonce but not in the quote (`GPUS_LOOSE`).

The gateway's session with the machine that ran a reply is named in its receipt, by the sha256 of
RedPill's public record of it (api.redpill.ai/v1/aci/sessions/{id}), which says which provider
that is. It is fetched only when Settings asks ("Name the provider behind each TEE reply", off by
default: `check` with `name_upstream`, `served_by`; from SealedLore 44e145d), since it goes to
api.redpill.ai directly, which then sees this computer's address: with no key, once a session a
process, at most a megabyte, believed only as the receipt names it, and never for a model Chutes
serves, whose instances have a session each, megabytes each.

nano-gpt's `TEE/*` models run inside a trusted execution environment. Two
calls let a client check that (docs.nano-gpt.com/api-reference/tee-verification):

- `GET {base}/tee/attestation?model=&nonce=` returns the enclave's
  `signing_address`, an Intel TDX quote (`intel_quote`) and NVIDIA GPU evidence
  (`nvidia_payload`), or, for a model Chutes answers, each instance's evidence.
  The quote's report data, read from its own bytes, must be the signing
  address, zero padding, then our nonce. With `&report=aci` (Nov 10 2026),
  RedPill's gateway's own report: its quote binds the gateway's whole keyset,
  the receipt key and the record-signing keys, to our nonce
  (`_attest_gateway`). Both are asked for, each with its own nonce. Each quote
  is verified up to Intel's pinned root, with Intel's revocation lists and TCB
  ratings (llm/dcap.py). The GPU evidence goes to NVIDIA's attestation service,
  and NVIDIA's signed answer must be for our nonce and pass
  (llm/nras.py). `attest` refuses (`TeeRefused`) or returns a "full" or
  "partial" attestation: see its docstring.
- `GET {base}/tee/signature/{receipt or completion id}?model=` returns a
  `text` and an EIP-191 `signature`; the signer recovered from them must be
  an attested address (llm/ethsig.py): the signing key the quote binds, or a
  key of the keyset the gateway's quote binds. Since Nov 2026 (RedPill's signed
  receipts; nano-gpt's fix of the lookup, which had answered 404) the text's
  `sha256(response)` is the hash of the exact bytes a stream carried, and the
  answer carries RedPill's receipt too (`check_reply`; from SealedLore's copy
  of this module, Nov 2026).

What this proves: a genuine, current, non-debug Intel TDX machine (and, when
evidence is offered, NVIDIA GPUs) holds the key, bound to our nonce; a record
for each reply was signed by that key, for the exact text received (where
nano-gpt passes a model's stream through); and, where read, the gateway's
receipt for that reply says its upstream was verified. What it doesn't
prove: which software that machine runs (no measurement is compared to a
published one), what was sent (the request is hashed as nano-gpt forwarded
it), or, where nano-gpt has no gateway report for a model, that the
receipt's key is in the quote (`RECEIPT_KEYS_LOOSE`). Nor is the call
end-to-end private: plaintext passes nano-gpt's gateway. For that, a
`private/` model (llm/private_mode.py). Every request to a TEE model is
streamed (llm/client.py, engine.py), so nano-gpt's exact mode for whole
replies (`X-NanoGPT-TEE-Response`) isn't needed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
import threading
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from .. import netpolicy as netguard
from . import dcap, nras
from .ethsig import keccak256, recover_personal
from .private_mode import relay_said
from .secure_http import ProviderError, loads, make_client

NRAS_URL = "https://nras.attestation.nvidia.com/v3/attest/gpu"
TIMEOUT_SECONDS = 30.0
# Chutes' evidence can take about a minute (nano-gpt, Nov 10 2026; live, 25 s
# for TEE/gemma4-31b:thinking's 40 instances, in SealedLore).
ATTESTATION_TIMEOUT_SECONDS = 90.0
# One attestation, all of it, is given this long: a request of it waits for what is left, and none
# is begun once it has passed (`TeeClient._left`). The endpoints may live under three paths, each
# asked in turn, for the gateway's report and then the model's own: with 90 seconds each to answer,
# an address that never did kept a model "attesting…" for nine minutes. Three minutes is a gateway's
# report, a model's own that timed out upstream (a 504, about a minute) asked for once more, and
# Intel's and NVIDIA's checks, with room to spare. The engine stops waiting soon after, whatever
# the attempt is doing (engine.py _attest_tee).
ATTEMPT_SECONDS = 180.0
# A stream's receipt is complete just after the stream ends (nano-gpt's own
# example waits up to about 20 seconds).
RECEIPT_WAIT_SECONDS = 20.0
RECEIPT_RETRY_SECONDS = 2.0
# A receipt is this request's only if the gateway served it between the request being sent and now:
# the response hash alone ties a receipt to a stream, and a relay could hand back an earlier signed
# stream with its receipt (or one for another prompt: the hashes are the gateway's own). This much
# leeway either way, for this computer's clock and the gateway's not quite agreeing. (SealedLore
# 1a61096, Nov 12 2026.)
RECEIPT_CLOCK_SKEW_SECONDS = 5 * 60
# Models whose streams nano-gpt rebuilds from the upstream's, so their bytes
# never match the receipt's hash (nano-gpt, Nov 2026).
REBUILT_STREAMS = frozenset({"TEE/gemma-4-31b-it"})
# Named in the attestation's shortfalls: the quote binds the key that signs
# each reply's record, not the receipt keys around it (where nano-gpt has no
# gateway report for the model, `_attest_gateway`).
RECEIPT_KEYS_LOOSE = "receipt keys not in the quote"
# Named in the attestation's shortfalls: what is attested is RedPill's
# gateway, which passes each request on to the model's host (from DA Vibe
# Manager's copy of this module, Nov 2026).
OWN_ENCLAVE_UNCHECKED = "the model's own enclave unchecked (RedPill's gateway)"
# Named in the attestation's shortfalls: a model Chutes answers first, which RedPill's gateway answers
# now and then, attested while nano-gpt had no gateway report for a reason but that RedPill doesn't
# serve it (a rate limit, an outage): whether the gateway may answer isn't known (`_attest_instances`).
GATEWAY_UNCHECKED = "RedPill's gateway unchecked"
# Named in the attestation's shortfalls too: NVIDIA vouched for GPU evidence made with our nonce, but
# the quote of the machine attested doesn't commit to it (nano-gpt's report: the signing address and
# our nonce, or the keyset and our nonce, and nothing of the GPUs), so the GPUs may be another
# machine's, the model's upstream say, relayed. Live, TEE/qwen3.6-35b-a3b's report carried 8 GPUs
# where RedPill's own record of its upstream (NEAR AI) has none (SealedLore 9af15c1, Nov 11 2026). A
# Chutes instance's quote binds its GPU evidence's nonce, so its GPUs are its own.
GPUS_LOOSE = "GPUs not tied to the quote"
# What each shortfall costs, as wherever an attestation is shown says it (the cross-app standard, Nov 14
# 2026: every shortfall has a tooltip saying what it costs; SealedLore's SHORTFALL_TIPS). An Intel TCB
# status other than these reads as Intel rating the machine below up to date (`shortfall_cost`).
SHORTFALL_COSTS = {
    OWN_ENCLAVE_UNCHECKED: (
        "The model's own enclave unchecked: what is attested is RedPill's TEE gateway, which passes each "
        "request on to the machine that runs the model. That machine isn't attested here: that it is a "
        "verified TEE is the gateway's word, in each reply's signed receipt. For an enclave attested "
        "itself, end to end, use a private/ model."),
    GATEWAY_UNCHECKED: (
        "RedPill's gateway unchecked: NanoGPT gave no report of the gateway just now (a rate limit, an "
        "outage, or an answer that couldn't be read, not that the gateway doesn't serve this model), and "
        "the gateway answers some of this provider's models now and then: a reply it answers can't be "
        "checked. Attesting again may find it."),
    RECEIPT_KEYS_LOOSE: (
        "Receipt keys not in the quote: NanoGPT had no gateway report for this model, so the hardware's "
        "quote binds the key that signs each reply's record, not the keys of the gateway's receipts, and "
        "a receipt's word that the model was verified rests on NanoGPT's relay."),
    "receipt keys expired": (
        "Receipt keys expired: the gateway's keyset names no time its keys hold until that can be read, so "
        "its receipts aren't read and no reply is verified by one. (Keys past their time are refused.)"),
    "no GPU evidence": (
        "No GPU evidence: none was offered, so no GPU was checked. For a model attested through RedPill's "
        "gateway, each reply's receipt carries the gateway's word that the model was verified."),
    GPUS_LOOSE: (
        "GPUs not tied to the quote: NVIDIA vouches for these GPUs, for this check, but the attested "
        "machine's quote doesn't commit to their evidence, so they may be another machine's (the one "
        "running the model, say), passed on."),
    "GPUs unverified": "GPUs unverified: NVIDIA's attestation service couldn't be reached, so no GPU was checked.",
    "NVIDIA signature unchecked": (
        "NVIDIA signature unchecked: NVIDIA's keys couldn't be fetched to check its signature; what its "
        "verdict says (our nonce, every GPU's result) was checked."),
    "Intel TCB unchecked": (
        "Intel TCB unchecked: Intel's revocation lists and ratings couldn't be fetched, so whether the "
        "machine's firmware is up to date isn't known."),
}


def shortfall_cost(what: str) -> str:
    """What a shortfall costs, for its tooltip: SHORTFALL_COSTS', or Intel's rating said plainly."""
    if what in SHORTFALL_COSTS:
        return SHORTFALL_COSTS[what]
    if what.startswith("Intel TCB "):
        return (f"{what}: Intel rates the machine's firmware or microcode below up to date: a fix it lacks "
                "may let its enclave be read.")
    return what
# RedPill's public records of its gateway's sessions with the machines that run the models (Settings
# → Model, "Name the provider behind each TEE reply", off by default: `TeeClient.served_by`). Each
# receipt's `upstream.verified` names its session by the sha256 of the record's RFC 8785 JSON, so the
# attested gateway's signature pins it whoever serves it. No key goes with it. (SealedLore 44e145d.)
SESSION_RECORDS = "https://api.redpill.ai/v1/aci/sessions/"
# A record past this is never read: a Chutes instance's is megabytes (3.4 MB for TEE/deepseek-v3.2,
# Nov 11 2026), and its replies spread over instances with a session each, so it would be megabytes
# nearly every message (the author: not that). Live, the others were 3 KB to 0.3 MB, one an hour a model.
SESSION_RECORD_MAX_BYTES = 1_000_000
# Records already read, by session id (content-addressed, so the same for every client), kept for the
# process: a session serves every reply its provider runs for an hour.
SESSION_RECORDS_KEPT = 64
_records: dict[str, _Record] = {}
_records_lock = threading.Lock()
# RedPill's names for its upstreams as a reply's mark shows them (`upstream_label`); any other is
# shown as RedPill writes it.
_UPSTREAM_LABELS = {
    "tinfoil": "Tinfoil",
    "phala": "Phala",
    "fortanix": "Fortanix",
    "armet": "Armet",
    "near-ai": "NEAR AI",
    "0g-private-computer": "0G",
    "chutes": "Chutes",
    "privatemode": "Privatemode",
}


@dataclass
class Attestation:
    """What a TEE check found (SealedLore's models/private.Attestation, TEE fields only).

    "full" when everything that can be checked was checked and held; "partial" when nothing
    failed but something couldn't be checked or isn't current, each named in `shortfalls`.
    A refused attestation is never one of these: TeeRefused, and nothing is sent."""

    verified: bool = False
    signing_address: str | None = None
    # Every key a reply's record may be signed by (lowercase addresses): the attested signing
    # key, or each key of the keyset the gateway's quote binds. Empty for a provider that signs
    # no replies.
    signers: list[str] = field(default_factory=list)
    nonce_ok: bool = False
    gpu_ok: bool | None = None
    checked_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds"))
    detail: str = ""
    level: str = ""
    shortfalls: list[str] = field(default_factory=list)
    tcb_status: str = ""
    gpus: int = 0
    instances: int = 0  # per-instance providers (Chutes): how many instances were attested
    # What was attested (`what_was_attested`): "gateway", RedPill's gateway, which passes the model's
    # requests on to the machine that runs it; "instances", each instance the provider (Chutes) listed;
    # "enclave", the one whose key signs the replies, not shown to be either. "" before Nov 11 2026.
    attested: str = ""

    @property
    def headline(self) -> str:
        """What the top bar says: "TEE gateway attested" where RedPill's gateway is what was
        attested, not the machine that runs the model."""
        return "TEE gateway attested" if self.attested == "gateway" else "TEE attested"

    @property
    def summary(self) -> str:
        parts = []
        if self.instances > 1:
            parts.append(f"{self.instances} instances")
        if self.gpus:
            parts.append(f"{self.gpus} GPU{'s' if self.gpus != 1 else ''} verified by NVIDIA")
        if self.tcb_status:
            parts.append(f"Intel TCB {self.tcb_status}")
        head = "Intel TDX quote verified" if self.level == "full" else (
            "partially verified: " + ", ".join(self.shortfalls))
        return head + (f" ({', '.join(parts)})" if parts else "")

    @property
    def costs(self) -> list[str]:
        """What each shortfall costs, in order (`shortfall_cost`): every one has its words."""
        return [shortfall_cost(what) for what in self.shortfalls]

    def to_dict(self) -> dict:
        return {**asdict(self), "summary": self.summary, "headline": self.headline,
                "what": what_was_attested(self), "costs": self.costs}


def what_was_attested(attestation: Attestation) -> str:
    """What an attestation that held was of, and what it leaves to someone's word, plainly: it
    leads the top bar's tooltip (the author, Nov 11 2026: "always make clear to the user what is
    actually happening and if it is properly attested or not"; SealedLore 9af15c1). Live, Nov 11
    2026: every model RedPill serves is attested as its gateway, which passes requests on to the
    model's own provider (Phala, Fortanix, NEAR AI, 0G, Tinfoil's router or Chutes, by RedPill's
    session records); a model Chutes serves itself, as its instances."""
    clear = (" Your text passes NanoGPT's servers in the clear on the way; a private/ model is "
             "end-to-end encrypted instead.")
    if attestation.attested == "gateway":
        return ("Attested: RedPill's TEE gateway, which NanoGPT sends this model's requests through and "
                "which passes them on to the machine that runs the model. That machine isn't attested by "
                "DA Vibe Manager: that it is a verified TEE is the gateway's word, in each reply's signed "
                "receipt." + clear)
    if attestation.attested == "instances":
        count = attestation.instances
        listed = f"each of the {count} instances" if count > 1 else "the instance"
        said = (f"Attested: {listed} this model's provider listed. They sign no replies, so nothing shows "
                "which machine answered a request: NanoGPT routes each one, and a model may be served "
                "elsewhere when its provider is busy.")
        if attestation.signers:
            said += (" A reply RedPill's gateway answers in their place is checked against the gateway's "
                     "attested keys, the machine behind it then the gateway's word.")
        return said + clear
    if attestation.attested == "enclave":
        return ("Attested: the enclave whose key signs this model's replies. Whether that machine runs the "
                "model itself or passes requests on isn't shown." + clear)
    return ""


@dataclass(frozen=True)
class TeeUpstream:
    """Who ran a TEE reply's model, by RedPill's record of its gateway's session with that machine
    (`TeeClient.served_by`; Settings → Model, "Name the provider behind each TEE reply", off by
    default). The record is RedPill's word, pinned by the receipt the attested gateway signed;
    nothing in it is checked by DA Vibe Manager. (SealedLore's models/private.TeeUpstream.)"""

    # RedPill's name for the provider ("tinfoil", "phala-244"); "" when none was named, `note`
    # saying why.
    name: str = ""
    # The verifier RedPill's gateway checked that machine with, what it vouched for
    # ("model_instance", "router", "near-ai-gateway"), and what RedPill says of its GPUs
    # ("asserted", "unknown").
    verifier: str = ""
    scope: str = ""
    gpus: str = ""
    # The model id the receipt names upstream ("gemma4-31b").
    model: str = ""
    note: str = ""
    # The session the receipt named, and whether api.redpill.ai was asked for its record for this
    # reply (False: none named, not looked up, or read once already this run): what was sent there.
    session: str = ""
    asked: bool = False

    def to_dict(self) -> dict:
        """As a reply's mark keeps it: with the name as shown and what it means (its tooltip)."""
        return {**asdict(self), "label": upstream_label(self) if self.name else "", "words": upstream_words(self)}


@dataclass(frozen=True)
class ReplyCheck:
    """What `TeeClient.check` found of a reply: its mark ("verified", "signed", "failed"), who
    ran its model, when asked to look, and whether its receipt was read under the attested keys
    and held (`receipt`). A model attested itself is verified without one (its own key signed the
    record), so the mark alone doesn't say: the mark's tooltip does, from this."""

    mark: str
    upstream: TeeUpstream | None = None
    receipt: bool = False


class Mark(str):
    """A reply's mark as `TeeClient.check_reply` gives it: the word, which also knows whether the
    reply's receipt was read and held (`receipt`, as ReplyCheck's)."""

    receipt: bool

    def __new__(cls, mark: str, receipt: bool = False) -> Mark:
        made = super().__new__(cls, mark)
        made.receipt = receipt
        return made


@dataclass(frozen=True)
class _Record:
    """What a session record says, read once (`_session_record`)."""

    name: str
    verifier: str
    scope: str
    gpus: str
    established: int
    expires: int


def upstream_label(upstream: TeeUpstream) -> str:
    """The provider as a reply's mark names it: "Tinfoil" for "tinfoil", "Phala" for "phala-244",
    else as RedPill writes it."""
    name = upstream.name
    return _UPSTREAM_LABELS.get(re.sub(r"-\d+$", "", name), name)


def upstream_words(upstream: TeeUpstream) -> str:
    """A reply's provider, said plainly, for its mark's tooltip: whose word it is, and what it
    doesn't prove."""
    if not upstream.name:
        return f"The provider that ran it wasn't named: {upstream.note}."
    scope = upstream.scope
    what = ("the machine that ran the model" if scope == "model_instance"
            else "its router, which passes requests on to the model" if scope == "router"
            else "its gateway, which passes requests on to the model" if "gateway" in scope
            else "it")
    gpus = {"asserted": "RedPill's verifier checked its GPUs",
            "unknown": "RedPill's record has no GPU attestation"}.get(upstream.gpus, "")
    model = f" (as {upstream.model})" if upstream.model else ""
    return (f"Run by {upstream_label(upstream)}{model}: RedPill's record of its gateway's session says its "
            f"verifier ({upstream.verifier or 'unnamed'}) checked {what}" + (f"; {gpus}" if gpus else "")
            + ". That is RedPill's word, fetched from api.redpill.ai and matched to the receipt the attested "
            "gateway signed; DA Vibe Manager doesn't check that machine.")


def _session_record(client: httpx.Client, session_id: str) -> _Record:
    """RedPill's record of one session, read once a process: from api.redpill.ai, with no key and
    nothing but the session's id, through the TEE client's guard (https only, no redirect followed,
    none off https or into this network) and its proxies, at most SESSION_RECORD_MAX_BYTES read a
    piece at a time, and believed only if the sha256 of its RFC 8785 JSON is the id the receipt
    named. Raises ProviderError, in words a tooltip can carry, for what kept it from being read."""
    with _records_lock:
        if session_id in _records:
            return _records[session_id]
    url = netguard.check(SESSION_RECORDS + session_id)
    body = bytearray()
    try:
        with client.stream("GET", url, timeout=TIMEOUT_SECONDS) as response:
            if response.status_code != 200:
                raise ProviderError(f"api.redpill.ai answered HTTP {response.status_code}")
            length = response.headers.get("content-length", "")
            if length.isdigit() and int(length) > SESSION_RECORD_MAX_BYTES:
                raise ProviderError(f"its record is {int(length) // 1000:,} KB, more than is read for one reply")
            for chunk in response.iter_bytes():
                body += chunk
                if len(body) > SESSION_RECORD_MAX_BYTES:
                    raise ProviderError("its record is more than is read for one reply")
    except httpx.HTTPError as exc:
        raise ProviderError(f"api.redpill.ai couldn't be reached ({type(exc).__name__})") from exc
    try:
        record = loads(bytes(body))      # nested past MAX_NESTING is refused as unreadable (secure_http.loads)
        named = isinstance(record, dict) and hashlib.sha256(_canonical(record)).hexdigest() == session_id
    except (ValueError, RecursionError) as exc:      # never the mark's concern (DA Vibe Manager's copy)
        raise ProviderError("RedPill's record couldn't be read") from exc
    if not named:
        raise ProviderError("the record api.redpill.ai sent isn't the one the receipt names")
    claims = record.get("claims") if isinstance(record.get("claims"), dict) else {}
    extra = claims.get("extra") if isinstance(claims.get("extra"), dict) else {}
    gpus = claims.get("gpu_attested") if isinstance(claims.get("gpu_attested"), dict) else {}
    established, expires = record.get("established_at"), record.get("expires_at")
    found = _Record(
        name=relay_said(str(record.get("upstream_name") or ""), 60),
        verifier=relay_said(str(record.get("verifier_id") or ""), 80),
        scope=relay_said(str(extra.get("evidence_scope") or extra.get("trust_boundary") or ""), 40),
        gpus=relay_said(str(gpus.get("status") or ""), 20),
        established=established if _integer(established) else 0,
        expires=expires if _integer(expires) else 0,
    )
    with _records_lock:
        while len(_records) >= SESSION_RECORDS_KEPT:
            _records.pop(next(iter(_records)))
        _records[session_id] = found
    return found


def _canonical(value: Any) -> bytes:
    """RFC 8785 JSON, which is this simple for documents of ASCII keys,
    strings and integers (RedPill's keysets and receipts)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _hex(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ValueError("not hex")
    return bytes.fromhex(value.removeprefix("0x"))


def _keyset_of(body: dict[str, Any]) -> dict[str, Any] | None:
    """RedPill's aci/1 `workload_keyset`, as nano-gpt relays it."""
    report = body.get("attestation")
    keyset = report.get("workload_keyset") if isinstance(report, dict) else None
    return keyset if isinstance(keyset, dict) else None


def _statement(keyset: dict[str, Any], nonce: str) -> bytes:
    """The report data RedPill's quote holds for a keyset and a nonce: the
    SHA-256 of its attestation statement, zero padded (its verifier's
    `computeReportData`, read Nov 2026)."""
    statement = (
        f'{{"keyset_digest":"{_digest(_canonical(keyset))}","nonce":"{nonce}",'
        '"purpose":"aci.report_data.v1"}'
    ).encode()
    return hashlib.sha256(statement).digest() + bytes(32)


def _holds_key(keyset: dict[str, Any], address: str) -> bool:
    """The keyset lists the secp256k1 key whose address is `address`: the
    gateway's e2ee key is the one it signs reply records with (live, Nov 2026)."""
    return any(
        _address_of_public(entry.get("public_key")) == address.lower()
        for entry in keyset.get("e2ee_public_keys") or []
        if isinstance(entry, dict)
    )


def _address_of_public(value: Any) -> str | None:
    """The address of an uncompressed secp256k1 public key (04...), lowercase."""
    try:
        key = _hex(value)
    except ValueError:
        return None
    if len(key) != 65 or key[0] != 4:
        return None
    return "0x" + keccak256(key[1:])[-20:].hex()


def _integer(value: Any) -> bool:
    """An integer as JSON writes one: never a bool, which Python counts as one."""
    return isinstance(value, int) and not isinstance(value, bool)


def _json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return loads(value)
        except ValueError:
            return None
    return value


def is_tee(model: str) -> bool:
    """A model that runs in a trusted execution environment: nano-gpt's
    `TEE/*` (attested and signed) or `private/*` (end-to-end encrypted),
    however it's written ("Tee/…", a space before it)."""
    return str(model or "").strip().lower().startswith(("tee/", "private/"))


def is_private_mode(model: str) -> bool:
    """nano-gpt's Private Mode: end-to-end encrypted to an attested enclave
    (llm/private_mode.py). Never sent any other way, however it's written
    ("Private/…", a space before it): when in doubt, sealed."""
    return str(model or "").strip().lower().startswith("private/")


def _bases(base_url: str) -> list[str]:
    """Where the TEE endpoints may live: the docs give the path three ways."""
    base = base_url.rstrip("/")
    parsed = urlparse(base)
    root = f"{parsed.scheme}://{parsed.netloc}"
    found = [base, f"{root}/api/v1", f"{root}/v1"]
    return list(dict.fromkeys(found))


def _error_text(response: httpx.Response) -> str:
    """The provider's message from an error response, or "": on one line, short, and without
    what can't be seen (`relay_said`), as everything of the relay's or the provider's that a
    refusal quotes is. It is shown in the top bar, logged, and, when a research run on the model
    fails, handed to the chat model as its tool's result. Until Nov 2026 only this was cut short,
    and a refusal could carry pages of the relay's text, line breaks and hidden characters."""
    try:
        body = loads(response.content)
    except (ValueError, RecursionError):
        return relay_said(response.text or "")
    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, dict):
            error = error.get("message")
        return relay_said(str(error or body.get("message") or ""))
    return ""


def _instance_key(certificate: bytes, body: bytes, signature: bytes) -> bytes | None:
    """sha256 of the certificate's public key (DER SubjectPublicKeyInfo) when its
    signature over `body` holds, else None (a Chutes instance's evidence)."""
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    try:
        key = x509.load_der_x509_certificate(certificate).public_key()
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, body, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, body, ec.ECDSA(hashes.SHA256()))
        else:
            return None
    except (InvalidSignature, ValueError):
        return None
    return hashlib.sha256(
        key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    ).digest()


class _Checks:
    """What one attestation's checks found, gathered across quotes and instances."""

    def __init__(self, *notes: str) -> None:
        self.notes = list(notes)
        self.shortfalls: list[str] = []
        self.status = ""
        self.gpus = 0

    def note(self, *notes: str) -> None:
        for note in notes:
            if note not in self.notes:
                self.notes.append(note)

    def fall_short(self, what: str) -> None:
        if what not in self.shortfalls:
            self.shortfalls.append(what)

    def tcb(self, status: str) -> None:
        """Keep the worst Intel TCB status seen."""

        def rank(value: str) -> int:
            return dcap.STATUSES.index(value) if value in dcap.STATUSES else len(dcap.STATUSES)

        if status and (not self.status or rank(status) > rank(self.status)):
            self.status = status

    def merge(self, other: _Checks) -> None:
        self.note(*other.notes)
        for what in other.shortfalls:
            self.fall_short(what)
        self.tcb(other.status)
        self.gpus += other.gpus

    def attestation(
        self,
        attested: str,
        *,
        signing_address: str | None = None,
        signers: frozenset[str] = frozenset(),
        instances: int = 0,
    ) -> Attestation:
        return Attestation(
            verified=True,
            level="partial" if self.shortfalls else "full",
            shortfalls=list(self.shortfalls),
            signing_address=signing_address,
            signers=sorted(signers),
            nonce_ok=True,
            gpu_ok=True if self.gpus else None,
            gpus=self.gpus,
            tcb_status=self.status,
            instances=instances,
            attested=attested,
            detail="; ".join(self.notes),
        )


class TeeRefused(ProviderError):
    """The enclave's attestation doesn't hold: nothing may be sent to it."""


@dataclass(frozen=True)
class _Gateway:
    """RedPill's gateway, attested for our nonce (`TeeClient._attest_gateway`)."""

    keyset: dict[str, Any]
    # The addresses of the secp256k1 keys the keyset lists: those that sign
    # each reply's record (the gateway's e2ee key, live Nov 2026; the X25519
    # e2ee key beside it signs nothing).
    signers: frozenset[str]
    check: _Checks


class TeeClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        *,
        client: httpx.Client | None = None,
        intel: Callable[..., dcap.Result] | None = None,
        nvidia: Callable[..., int] | None = None,
        wall: Callable[[], float] = time.time,
    ) -> None:
        # https, or a local address: the key goes there; and a key no header can carry is sent nowhere
        # (DA Vibe Manager's copy, Nov 2026)
        netguard.check(base_url)
        netguard.check_key(api_key, urlparse(base_url).hostname or "the provider")
        self.base_url = base_url
        self.api_key = api_key
        self.model = model
        self._client = client or make_client(base_url, timeout=httpx.Timeout(TIMEOUT_SECONDS))
        self._owns = client is None
        self.signing_address: str | None = None
        # Who may sign a reply's record: the attested signing key, or every
        # key of the keyset a quote binds (lowercase addresses).
        self.signers: frozenset[str] = frozenset()
        # Attested by its instances (Chutes), whose replies carry no record.
        self.instances = False
        # Attested through RedPill's gateway alone (`_attest_gateway_alone`): a reply is verified
        # only with a receipt that holds under the attested keys, the gateway's word that the
        # model's own enclave answered it (SealedLore's rule, dd39efc, Nov 11 2026).
        self.receipt_required = False
        # The receipt keys, when tied to the attested quote (`_take_keyset`).
        self.keyset: dict[str, Any] | None = None
        self.keyset_digest: str | None = None
        self._base: str | None = None
        # The two verifiers, replaceable so tests can stand in for Intel and NVIDIA.
        self._intel = intel or dcap.verify
        self._nvidia = nvidia or nras.verify
        # The time of day, which receipts are dated in (`served_at`, Unix seconds): a receipt holds
        # only if served between its request being sent and now (`_receipt_holds`). Replaceable for
        # tests.
        self._wall = wall
        # When the attestation under way must be over (time.monotonic; `ATTEMPT_SECONDS`), else None.
        self._deadline: float | None = None
        # The checks of replies under way, and whether `close` was called: the http client is
        # closed once none uses it (`_in_use`).
        self._using = 0
        self._closed = False
        self._lock = threading.Lock()

    def close(self) -> None:
        """Close the http client, once no check of a reply still uses it. The engine closes a
        client whose attestation was made again, refused or forgotten, while a turn that began
        under it may still have its replies to check: a check under way keeps the client until it
        ends, and one begun after it was closed opens it again for as long as it runs
        (`_in_use`). Until Nov 2026 a client replaced was never closed, and one forgotten was
        closed under the checks still using it, which then read as "unchecked"."""
        if not self._owns:
            return
        with self._lock:
            self._closed = True
            if not self._using:
                self._client.close()

    @contextmanager
    def _in_use(self) -> Iterator[None]:
        """While a reply is checked: the http client is open, and stays so (`close`)."""
        with self._lock:
            if self._owns and self._client.is_closed:
                self._client = make_client(self.base_url, timeout=httpx.Timeout(TIMEOUT_SECONDS))
            self._using += 1
        try:
            yield
        finally:
            with self._lock:
                self._using -= 1
                if self._owns and self._closed and not self._using:
                    self._client.close()

    def _left(self, wanted: float = TIMEOUT_SECONDS) -> float:
        """How long a request of the attestation under way may wait: `wanted`, or what is left of
        `ATTEMPT_SECONDS` when that is less. Refuses once it has passed: asked before each
        request, and before Intel's and NVIDIA's checks. Outside an attestation (a reply's
        check), `wanted`."""
        if self._deadline is None:
            return wanted
        left = self._deadline - time.monotonic()
        if left <= 0:
            raise TeeRefused(
                f"{self.model}'s attestation wasn't done within {ATTEMPT_SECONDS / 60:g} minutes, "
                "and was given up; this may pass if tried again"
            )
        return min(wanted, left)

    def _get(
        self,
        path: str,
        params: dict[str, str],
        *,
        route: str | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        if route:
            # nano-gpt names a route on a reply now and then: its checks name it too.
            headers["X-TEE-Verification-Route"] = route
        last: str = ""
        last_status: int | None = None
        for base in [self._base] if self._base else _bases(self.base_url):
            if self._deadline is not None:
                # of an attestation: each address waits only for what is left of its time
                timeout = self._left(TIMEOUT_SECONDS if timeout is None else timeout)
            try:
                response = self._client.get(
                    f"{base}{path}",
                    params=params,
                    headers=headers,
                    **({"timeout": timeout} if timeout is not None else {}),
                )
            except httpx.HTTPError as exc:
                last, last_status = netguard.scrubbed(exc), None
                continue
            if response.status_code == 404:
                last, last_status = f"{netguard.shown(base + path)}: 404", 404
                continue
            if response.status_code >= 400:
                # nano-gpt's own words, when it gives any: "Unable to reach RedPill
                # attestation service" says far more than a status code.
                reason = _error_text(response)
                raise ProviderError(
                    f"nano-gpt answered HTTP {response.status_code}"
                    + (f": {reason}" if reason else ""),
                    status_code=response.status_code,
                    body=reason,
                )
            try:
                body = loads(response.content)
            except (ValueError, RecursionError) as exc:    # or JSON nested past reading
                raise ProviderError(f"{netguard.shown(base + path)} returned a non-JSON body") from exc
            if not isinstance(body, dict):
                raise ProviderError(f"{netguard.shown(base + path)} returned {type(body).__name__}")
            self._base = base
            return body
        raise ProviderError(f"no TEE endpoint answered ({last})", status_code=last_status)

    def attest(self) -> Attestation:
        """Check the enclave now, with a fresh nonce (network; a worker thread).

        nano-gpt's TEE/ models come from more than one provider, attesting in two
        shapes (both measured live, Sept 2026; ported from the author's
        AI-Assistant app):

        - aci/1: RedPill's gateway, whose TDX quote binds its reply-signing key and
          our nonce, with GPU evidence of the upstream node made with our nonce
          (`_attest_signing_key`; partial: the model's own enclave isn't shown);
        - per instance (Chutes: TEE/kimi-k3 and others): a list of instances, each
          quote binding that instance's own key, which signs a body carrying our
          nonce, the quote and the GPU evidence (`_attest_instances`).

        Beside it, with a nonce of its own, RedPill's gateway's own report
        (`report=aci`, Nov 10 2026: `_attest_gateway`), whose quote binds the
        gateway's whole keyset to our nonce. Where it holds, a signing key in
        that keyset takes the bound receipt keys; a model whose own report was
        relayed for a nonce not ours, or timed out, is attested through the
        gateway alone (`_attest_gateway_alone`); and a Chutes model's reply
        RedPill answers instead is checked against the gateway's keys. Where
        nano-gpt has none (a model only Chutes or Tinfoil serves, an outage),
        the model's own report is taken as before.

        Refuses (`TeeRefused`, and nothing may be sent) when an enclave can't be
        trusted: no attestation, a quote that doesn't bind our nonce (directly, or
        by a key the quote binds), a quote Intel's chain doesn't vouch for (forged,
        revoked, a debug TD, a TCB Intel revoked or never listed), GPU evidence
        whose NVIDIA verdict is unsigned, stale, for another nonce or negative
        (llm/dcap.py, llm/nras.py), any instance that failed to attest
        (a request could be routed to it), evidence relayed for a nonce the
        relay chose (RedPill: replayable) with no attested gateway to stand in,
        a gateway report in RedPill's shape that doesn't bind our nonce, or
        attested keys past their expiry.

        What merely couldn't be checked (Intel's collateral or NVIDIA's service out
        of reach, no GPU evidence offered) or isn't current (any Intel TCB status
        but UpToDate) makes the attestation "partial", each reason in `shortfalls`.

        Until Sept 2026 a nonce that merely came back in nano-gpt's JSON counted,
        the report data was read from nano-gpt's copy, and neither Intel's nor
        NVIDIA's signatures were checked. Anything can echo a string.

        Evidence that isn't in the shape it should be (a list where an object belongs, a key
        that isn't hex, JSON nested past reading) refuses like any other that doesn't hold, as
        a TeeRefused that says it couldn't be read, the error it raised its cause: until Nov
        2026 that error itself (an AttributeError, a TypeError) reached the top bar. And the
        whole of it is given `ATTEMPT_SECONDS`.
        """
        self._deadline = time.monotonic() + ATTEMPT_SECONDS
        try:
            return self._attest()
        except (ProviderError, ImportError):     # a refusal already; or no cryptography, which says so itself
            raise
        except Exception as exc:  # noqa: BLE001 - whatever reading the evidence raised, it is refused
            raise TeeRefused(
                f"{self.model}'s attestation couldn't be read: what its provider sent isn't in the "
                f"shape it should be ({type(exc).__name__})"
            ) from exc
        finally:
            self._deadline = None

    def _attest(self) -> Attestation:
        """`attest`'s checks, in their order."""
        self.signing_address = None
        self.signers = frozenset()
        self.keyset = self.keyset_digest = None
        self.instances = False
        self.receipt_required = False
        gateway, unheard = self._attest_gateway()
        try:
            body, nonce = self._fetch_attestation()
        except ProviderError as exc:
            # Only a timeout lets the gateway stand in (live, Nov 10 2026: TEE/qwen3.6-27b's
            # report, a 504 twice). SealedLore lets it stand in for any failure, but a refusal
            # (400), a rate limit (429) or an outage says nothing of where the model's requests go,
            # and for a model Chutes answers first the gateway's report covers none of the
            # instances that answer most of them: live, a 429 had TEE/glm-5.1 attested through the
            # gateway alone, its 12 instances unchecked. A Chutes model whose evidence times out
            # still is: its instances' replies then show as not verified, never as verified.
            if gateway is not None and exc.status_code == 504:
                return self._attest_gateway_alone(gateway, "its own attestation timed out")
            if isinstance(exc, TeeRefused):      # out of time (`_left`): said as it is
                raise
            raise self._refused(exc) from exc
        if isinstance(body.get("evidence"), list):
            return self._attest_instances(body, nonce, gateway, unheard)
        if isinstance(body.get("all_attestations"), list) and "signing_address" not in body:
            # RedPill relaying Chutes (live, Sept 2026: TEE/glm-5.1, TEE/qwen3.5-27b,
            # TEE/qwen3.5-397b-a17b; Nov 10 2026: TEE/deepseek-v3.2). The quotes are
            # made for a nonce the relay chose, not ours nor derived from it, and
            # nothing signed ties them to ours: they would read the same replayed
            # from any earlier day. The gateway that answers, attested for our
            # nonce, can stand in (`_attest_gateway_alone`).
            if gateway is not None:
                return self._attest_gateway_alone(
                    gateway, "its upstream's evidence was relayed for a nonce not ours"
                )
            why = (
                "made for a nonce the relay chose, not ours"
                if body.get("nonce") != nonce
                else "carries no binding of our nonce this app can check"
            )
            raise TeeRefused(
                f"{self.model}'s attestation, relayed by its provider "
                f"({relay_said(str(body.get('attestation_type') or ''), 40) or 'unnamed'}), was {why}, "
                "so it can't show the enclave is live for this request"
            )
        if body.get("signing_address") or body.get("intel_quote"):
            return self._attest_signing_key(body, nonce, gateway)
        # Nor does one that holds nothing to check (SealedLore's gateway stands in for it too),
        # for the same reason. What it holds instead is the relay's to write: said short, on one
        # line, without what can't be seen (`_error_text`).
        if body.get("error"):
            raise TeeRefused(f"nano-gpt couldn't attest {self.model}: {relay_said(str(body['error']))}")
        raise TeeRefused(
            f"{self.model}'s attestation is in a shape this app doesn't recognise "
            f"(it holds {relay_said(', '.join(sorted(body))) or 'nothing'})"
        )

    def _fetch_attestation(self, *, aci: bool = False) -> tuple[dict[str, Any], str]:
        """nano-gpt's attestation for a fresh nonce, and the nonce. A 504 (the
        provider's evidence took too long: `tee_attestation_upstream_timeout`)
        is asked once more with a new nonce, as nano-gpt says to.

        No `X-TEE-Verification-Route` goes with it, though nano-gpt reads one
        here too (nor does SealedLore send one): attestation comes before the
        request, so no reply has named a route yet, and a route a past reply
        named would pin the next attestation to that reply's route (nano-gpt
        answers with that route's report: for a Chutes model, RedPill's in
        place of the instances it is routed to first), or, an hour old, make it
        answer 400, a refusal. Without one, both routes a model may take are
        attested: its own report, and the gateway's (`report=aci` needs none).
        The route goes on the signature lookups (`_signature`)."""
        for attempt in range(2):
            nonce = secrets.token_hex(32)
            params = {"model": self.model, "nonce": nonce}
            if aci:
                params["report"] = "aci"
            try:
                body = self._get("/tee/attestation", params, timeout=ATTESTATION_TIMEOUT_SECONDS)
            except ProviderError as exc:
                if exc.status_code == 504 and not attempt:
                    continue
                raise
            return body, nonce
        raise AssertionError("unreachable")  # pragma: no cover

    def _refused(self, exc: ProviderError) -> TeeRefused:
        """Why the attestation couldn't be had, as a refusal."""
        reason = exc.body or ""
        if exc.status_code == 400:
            # Live (Sept 2026): the Tinfoil-hosted TEE/ models offer no
            # attestation here; nano-gpt says fresh attestation for them only
            # comes through Tinfoil's own flow, the one their private/ twins use.
            hint = (
                "; its end-to-end encrypted private/ version, where nano-gpt offers "
                "one, is attested that way"
                if "tinfoil" in reason.lower()
                else ""
            )
            return TeeRefused(
                f"{self.model} offers no attestation"
                + (f" (nano-gpt: {reason})" if reason else "")
                + hint
            )
        if exc.status_code is not None and exc.status_code >= 500:
            return TeeRefused(
                f"nano-gpt couldn't fetch {self.model}'s attestation just now ({exc}); "
                "this is on the provider's side, and may pass if tried again"
            )
        return TeeRefused(f"{self.model}'s attestation couldn't be fetched: {exc}")

    def _attest_gateway(self) -> tuple[_Gateway | None, str]:
        """RedPill's gateway, attested for our nonce (`report=aci`, nano-gpt,
        Nov 10 2026), or None where nano-gpt has no such report: a model only
        Chutes or Tinfoil serves (HTTP 400), an outage, or another shape. With
        it, why there was none, where that wasn't RedPill not serving the model
        (an outage, a rate limit, a 200 in a shape that can't be read:
        `_attest_instances`), else "". Only a 400, nano-gpt's "not offered",
        says the gateway doesn't answer the model (the standard every DA app
        keeps, Nov 14 2026: an answer that can't be read is no report, and
        falls short, never full).

        The quote's report data is the SHA-256 of RedPill's attestation
        statement, the gateway's whole keyset and our nonce, zero padded
        (`_statement`): the hardware binds the receipt key and the keys that
        sign each reply's record, which nano-gpt's other report doesn't (it
        binds one signing key, the keyset published beside it). Every model
        RedPill serves is answered by the same gateway image (live, in
        SealedLore: 14 of 14 quotes alike, plain and aci). Refuses a report in
        RedPill's shape that doesn't bind our nonce, Intel doesn't vouch for,
        or whose keys are past their expiry."""
        try:
            body, nonce = self._fetch_attestation(aci=True)
        except ProviderError as exc:
            return None, "" if exc.status_code == 400 else str(exc)[:200]
        report = body.get("attestation") if body.get("api_version") == "aci/1" else None
        evidence = report.get("evidence") if isinstance(report, dict) else None
        keyset = report.get("workload_keyset") if isinstance(report, dict) else None
        if not (isinstance(evidence, dict) and isinstance(keyset, dict) and evidence.get("quote")):
            return None, "its answer wasn't in a shape that can be read"
        try:
            raw = bytes.fromhex(str(evidence["quote"]))
            quote = dcap.parse_quote(raw)
        except (ValueError, dcap.DcapError) as exc:
            raise TeeRefused(
                f"{self.model}'s gateway's Intel TDX quote couldn't be read ({exc})"
            ) from exc
        # From the quote's own bytes, never nano-gpt's copy (`report_data`,
        # `quote_report_data`).
        if quote.report_data != _statement(keyset, nonce):
            raise TeeRefused(f"{self.model}'s gateway didn't bind its keys to our nonce")
        self._refuse_expired(keyset)
        check = _Checks("the gateway's Intel TDX quote binds its keys to our nonce")
        self._check_quote(raw, check)
        signers = frozenset(
            address
            for entry in keyset.get("e2ee_public_keys") or []
            if isinstance(entry, dict)
            and (address := _address_of_public(entry.get("public_key"))) is not None
        )
        return _Gateway(keyset=keyset, signers=signers, check=check), ""

    def _refuse_expired(self, keyset: dict[str, Any] | None) -> None:
        """Keys the gateway's keyset holds only until a time now past are
        refused (DA Vibe Manager's rule): what was attested is keys no longer
        in force. A keyset that names no such time isn't used for the receipts,
        and falls short (`_take_keyset`)."""
        expires = keyset.get("not_after") if keyset is not None else None
        # an integer: a bool is one to Python, and `not_after: true` (1, in 1970) was refused as expired;
        # a bool, a float or none at all is unusable, and falls short instead (`_take_keyset`)
        if _integer(expires) and expires < time.time():
            raise TeeRefused(f"{self.model}'s attested keys expired on {datetime.fromtimestamp(expires, UTC):%Y-%m-%d}")

    def _attest_gateway_alone(self, gateway: _Gateway, why: str) -> Attestation:
        """The gateway, attested for our nonce, stands for a model whose own
        attestation timed out or can't be checked (live, Nov 10 2026, in
        SealedLore: TEE/deepseek-v3.2, relayed for a nonce not ours;
        TEE/qwen3.6-27b, a 504). Its replies are signed by the gateway's bound keys and carry its
        receipts; the model's own enclave and GPUs are then the gateway's word
        in each receipt (`upstream.verified`), not checked here: so it falls
        short, of GPU evidence and of the model's own enclave. And a reply is
        verified only with a receipt that holds (`receipt_required`, `check_reply`):
        without one, the gateway's signature says only that the reply passed
        through it."""
        check = _Checks(f"{why}: the gateway that answers it is attested instead")
        check.merge(gateway.check)
        check.fall_short("no GPU evidence")
        check.fall_short(OWN_ENCLAVE_UNCHECKED)
        check.note(
            "its own enclave isn't attested here: each reply's receipt carries the "
            "gateway's word that its upstream was verified"
        )
        self.signers = gateway.signers
        self.receipt_required = True
        self._take_keyset(gateway.keyset, "the quote binds its receipt keys", check)
        return check.attestation("gateway", signers=self.signers)

    def _attest_signing_key(
        self, body: dict[str, Any], nonce: str, gateway: _Gateway | None = None
    ) -> Attestation:
        """aci/1: one enclave, its reply-signing key and our nonce in its quote."""
        address = body.get("signing_address")
        address = address if isinstance(address, str) and address.startswith("0x") else None
        if address is None:
            raise TeeRefused(f"{self.model}'s attestation named no signing key")
        try:
            raw = bytes.fromhex(str(body.get("intel_quote") or ""))
            quote = dcap.parse_quote(raw)
        except (ValueError, dcap.DcapError) as exc:
            raise TeeRefused(f"{self.model}'s Intel TDX quote couldn't be read ({exc})") from exc
        # From the quote's own bytes, the part Intel's chain signs, never from
        # nano-gpt's JSON copy. Either the signing address, zero padding and our
        # nonce (as nano-gpt serves it), or RedPill's own attestation statement:
        # the gateway's keyset and our nonce, the signing key in that keyset.
        report_data = quote.report_data
        keyset = _keyset_of(body)
        holds = keyset is not None and _holds_key(keyset, address)
        signers = frozenset({address.lower()})
        # The signing key is one of the keys the gateway's own quote binds.
        bound_by_gateway = gateway is not None and address.lower() in gateway.signers
        statement = False      # the quote is RedPill's own statement of its keyset (below)
        if (
            report_data[:20] == bytes.fromhex(address[2:])
            and not any(report_data[20:32])
            and report_data[32:] == bytes.fromhex(nonce)
        ):
            check = _Checks("the Intel TDX quote binds the signing key to our nonce")
            if bound_by_gateway and gateway is not None:
                # The gateway's report binds the keyset this key is in: the
                # receipt key is the hardware's too (nano-gpt's report=aci, Nov
                # 10 2026). Its keys sign records as this one does.
                check.merge(gateway.check)
                keyset, signers = gateway.keyset, gateway.signers
                tie = "the gateway's quote binds its receipt keys, the signing key among them"
            else:
                tie = (
                    "its receipt keys are published beside the attested signing key"
                    if holds
                    else ""
                )
                # The receipts' word that the model was verified then rests on
                # the relay's JSON, not the hardware, and the same with no
                # keyset at all: said either way, so leaving it out never reads
                # better than sending it.
                check.fall_short(RECEIPT_KEYS_LOOSE)
                if gateway is not None:
                    check.note("the gateway's attested keys don't include the signing key")
        elif keyset is not None and holds and report_data == _statement(keyset, nonce):
            check = _Checks(
                "the Intel TDX quote binds the gateway's keys, its signing key among them, "
                "to our nonce"
            )
            tie = "the quote binds its receipt keys"
            statement = True
        else:
            raise TeeRefused(f"{self.model}'s attestation didn't bind its signing key to our nonce")
        self._refuse_expired(keyset)
        caps = body.get("service_capabilities") if isinstance(body.get("service_capabilities"), dict) else {}
        # RedPill's gateway: the signing key is one its own report binds, the quote is RedPill's
        # statement of its keyset, or the report says it is RedPill's (aci/1, an aggregator). What
        # is attested is then the gateway, not the machine that runs the model (`what_was_attested`).
        gateway_attested = (bound_by_gateway or statement
                            or body.get("api_version") == "aci/1" or caps.get("serving") == "aggregator")
        if gateway_attested:
            # RedPill's gateway (live, Nov 2026: the same key since Sept; a key its own report binds,
            # since Nov 10): it passes requests on to the model's host. Its quote is the gateway's; the
            # GPU evidence is an upstream node's, made with our nonce but not bound to that quote; that
            # the model itself runs in an enclave isn't shown here (RedPill says it in a signed receipt
            # per reply). From DA Vibe Manager's copy of this module (Nov 2026).
            check.fall_short(OWN_ENCLAVE_UNCHECKED)
            check.note("this is RedPill's gateway, which passes each request on to the model's host: the gateway's "
                       "quote and the GPUs' evidence are checked, not that the model itself runs in an enclave")
        self._check_quote(raw, check)
        payload = _json(body.get("nvidia_payload"))
        payload = payload if isinstance(payload, dict) else None
        self._check_gpus(payload, nonce, check, "this request's nonce")
        if payload is not None and payload.get("evidence_list"):
            # The quote's report data is the signing key and our nonce (or the keyset and our
            # nonce): nothing in it commits to the GPU evidence (SealedLore 9af15c1).
            check.fall_short(GPUS_LOOSE)
            check.note("the quote doesn't commit to the GPU evidence, so the GPUs may be another machine's")
        self.signing_address = address
        self.signers = signers
        self._take_keyset(keyset if tie else None, tie, check)
        return check.attestation("gateway" if gateway_attested else "enclave", signing_address=address,
                                 signers=signers)

    def _take_keyset(self, keyset: dict[str, Any] | None, tie: str, check: _Checks) -> None:
        """The gateway's receipt-signing keys (RedPill's aci/1 `workload_keyset`),
        kept for the receipts (`check_reply`) only when tied to the quote: it
        commits to them (RedPill's statement, or the gateway's report=aci), or
        they are published with the signing key it binds (nano-gpt's other
        report, Nov 2026). The second is the weaker tie:
        the quote binds that key, not the keyset around it. A keyset tied
        neither way, or expired, is not used, and receipts go unread."""
        self.keyset = self.keyset_digest = None
        if keyset is None:
            return
        not_after = keyset.get("not_after")
        if not _integer(not_after) or not_after <= time.time():
            # past, or no time it can be read as (missing, a bool, a float, text): unused for receipts
            check.note("its receipt keys have expired, so receipts aren't checked")
            check.fall_short("receipt keys expired")
            return
        self.keyset, self.keyset_digest = keyset, _digest(_canonical(keyset))
        check.note(tie)

    def _attest_instances(
        self, body: dict[str, Any], nonce: str, gateway: _Gateway | None = None, unheard: str = ""
    ) -> Attestation:
        """Per instance: each quote binds an instance key, which signed our nonce.

        For each instance, all of these before it counts:
        - its certificate's public key hashes to the second half of its quote's
          report data, so the key belongs to that TD (the certificate's issuer, the
          provider's private CA, is not a trust anchor and isn't relied on);
        - that key's signature over `attested_body` verifies, and the body carries
          our nonce and exactly this quote: an instance whose key the hardware
          vouches for answered this request;
        - the quote passes Intel's checks, like any other;
        - the GPU evidence (the signed copy) passes NVIDIA's checks. It is made
          with the first half of the report data as its nonce (measured live:
          NVIDIA's verdict matches that and nothing else), so it is bound to the
          quote, and through the signature to this request.
        The instances are checked in parallel; the attestation takes the worst.

        A model Chutes answers first falls back to RedPill now and then (nano-gpt,
        Nov 10 2026): with the gateway attested too, such a reply's record and
        receipt are checked against its bound keys, and the gateway's checks
        count with the instances'. A request may then go through RedPill's
        gateway, whose host is its word, not attested here, so the model falls
        short as any the gateway answers does (`OWN_ENCLAVE_UNCHECKED`; DA
        Assistant and DA Vibe Manager read it so too; SealedLore counts it whole).
        Where nano-gpt had no gateway report for a reason but that RedPill doesn't
        serve the model (`unheard`: a rate limit, an outage), whether the gateway
        may answer isn't known: that falls short too (`GATEWAY_UNCHECKED`), so an
        outage never reads better than the report would.
        """
        failed = [str(i) for i in body.get("failed_instance_ids") or []]
        instances = body["evidence"]
        if failed:
            raise TeeRefused(
                f"{len(failed)} of {len(failed) + len(instances)} of {self.model}'s "
                "instances couldn't be attested, and a request could be routed to one"
            )
        if not instances:
            raise TeeRefused(f"{self.model}'s attestation listed no instances")
        with ThreadPoolExecutor(max_workers=min(8, len(instances))) as pool:
            results = list(pool.map(lambda item: self._check_instance(item, nonce), instances))
        check = _Checks(
            f"each of {len(instances)} instances' keys, bound into its TDX quote, signed our nonce"
        )
        for result in results:
            check.merge(result)
        self.instances = True
        if gateway is None:
            if unheard:
                check.fall_short(GATEWAY_UNCHECKED)
                check.note(
                    f"nano-gpt gave no report of RedPill's gateway just now ({unheard}), and it "
                    "answers some models Chutes serves first now and then: such a reply can't be checked"
                )
            attestation = check.attestation("instances", instances=len(instances))
            attestation.detail += "; this provider signs no replies, so answers show as unsigned"
            return attestation
        check.merge(gateway.check)
        check.fall_short(OWN_ENCLAVE_UNCHECKED)
        self.signers = gateway.signers
        self._take_keyset(
            gateway.keyset,
            "a reply RedPill's gateway answers instead is checked against its attested keys, "
            "the model's own enclave behind it then the gateway's word in its receipt",
            check,
        )
        attestation = check.attestation("instances", signers=self.signers, instances=len(instances))
        attestation.detail += "; the instances sign no replies, so their answers show as unsigned"
        return attestation

    def _check_instance(self, item: dict[str, Any], nonce: str) -> _Checks:
        name = relay_said(str(item.get("instance_id") or ""), 8) or "an instance"
        try:
            raw = base64.b64decode(item["quote"])
            quote = dcap.parse_quote(raw)
            signed = base64.b64decode(item["attested_body"])
            certificate = base64.b64decode(item["certificate"])
            signature = base64.b64decode(item["signature"])
        except (KeyError, TypeError, ValueError, binascii.Error, dcap.DcapError) as exc:
            raise TeeRefused(
                f"{self.model}'s instance {name} sent unreadable evidence ({exc})"
            ) from exc
        key_hash = _instance_key(certificate, signed, signature)
        if key_hash is None:
            raise TeeRefused(
                f"{self.model}'s instance {name} didn't sign its evidence with the key it presented"
            )
        if quote.report_data[32:] != key_hash:
            raise TeeRefused(
                f"{self.model}'s instance {name} signed with a key its TDX quote doesn't bind"
            )
        try:
            attested = loads(signed)
            evidence = attested["evidence"]
        except (ValueError, KeyError, TypeError) as exc:
            raise TeeRefused(f"{self.model}'s instance {name} signed unreadable evidence") from exc
        if attested.get("nonce") != nonce:
            raise TeeRefused(f"{self.model}'s instance {name} didn't sign our nonce")
        # the signed copy of the quote: "quote" since Chutes renamed it (seen Nov 8 2026), "tdx_quote" before
        signed_quote = evidence.get("quote") or evidence.get("tdx_quote") or ""
        if base64.b64decode(signed_quote) != raw:
            raise TeeRefused(f"{self.model}'s instance {name} signed a different quote")
        check = _Checks()
        self._check_quote(raw, check)
        gpu = _json(evidence.get("nvtrust_evidence"))
        payload = None
        gpu_nonce = quote.report_data[:32].hex()
        if isinstance(gpu, list) and gpu:
            payload = {
                "nonce": gpu_nonce,
                "arch": gpu[0].get("arch", "HOPPER"),
                "evidence_list": gpu,
            }
        self._check_gpus(payload, gpu_nonce, check, "the nonce its quote binds")
        return check

    def _check_quote(self, raw: bytes, check: _Checks) -> None:
        """Intel's verification of one quote, into `check`. Refuses a bad quote, and one whose
        verification raised anything else: it couldn't be read. Why is said short and on one
        line (`relay_said`): a refusal can name a certificate of the quote's own chain, which
        its sender wrote."""
        self._left()
        try:
            intel = self._intel(raw, self._client)
        except dcap.DcapError as exc:
            raise TeeRefused(
                f"{self.model}'s Intel TDX quote failed verification: {relay_said(str(exc), 300)}"
            ) from exc
        except (ProviderError, ImportError):
            raise
        except Exception as exc:  # noqa: BLE001 - not verified, whatever it raised
            raise TeeRefused(
                f"{self.model}'s Intel TDX quote couldn't be read ({type(exc).__name__})"
            ) from exc
        check.note(*intel.notes)
        check.tcb(intel.status)
        if not intel.collateral:
            check.fall_short("Intel TCB unchecked")
        elif intel.status != "UpToDate":
            check.fall_short(f"Intel TCB {intel.status}")

    def _check_gpus(
        self, payload: dict[str, Any] | None, nonce: str, check: _Checks, bound_to: str
    ) -> None:
        """NVIDIA's verdict on one set of GPU evidence, into `check`."""
        if not (isinstance(payload, dict) and payload.get("evidence_list")):
            # Live, several TEE/ models send an empty evidence list: not a
            # rejection, but nothing for NVIDIA to vouch for either.
            check.fall_short("no GPU evidence")
            check.note("no GPU evidence was offered")
            return
        answer = self._nras_answer(payload)
        if answer is None:
            check.fall_short("GPUs unverified")
            check.note("NVIDIA's attestation service couldn't be reached")
            return
        try:
            gpus = self._nvidia(answer, nonce, self._client)
        except nras.KeysUnavailable as exc:
            # Only NVIDIA's signature is unchecked: nras.verify held its verdict to our nonce,
            # its issuer, its validity and every GPU's result before saying so.
            check.fall_short("NVIDIA signature unchecked")
            check.note(f"{exc}, so NVIDIA's verdict is unchecked")
        except nras.NrasError as exc:
            raise TeeRefused(
                f"{self.model}'s GPU attestation failed: {relay_said(str(exc), 300)}"
            ) from exc
        except (ProviderError, ImportError):
            raise
        except Exception as exc:  # noqa: BLE001 - not verified, whatever it raised
            raise TeeRefused(
                f"{self.model}'s GPU attestation couldn't be read ({type(exc).__name__})"
            ) from exc
        else:
            check.gpus += gpus
            check.note(
                f"NVIDIA's signed verdict vouches for {gpus} GPU{'s' if gpus != 1 else ''}, "
                f"for {bound_to}"
            )

    def _nras_answer(self, payload: Any) -> Any:
        """NVIDIA's answer to the GPU evidence, or None if the service couldn't be
        reached. HTTP 4xx is NVIDIA refusing the evidence: that refuses. (It used
        to read "rejected" for an outage too.)"""
        try:
            response = self._client.post(NRAS_URL, json=payload, timeout=self._left())
        except httpx.HTTPError:
            return None
        if response.status_code >= 500:
            return None
        if response.status_code >= 400:
            raise TeeRefused(
                f"NVIDIA rejected {self.model}'s GPU evidence (HTTP {response.status_code})"
            )
        try:
            return loads(response.content)
        except ValueError:
            return None

    def verify_reply(
        self,
        response_id: str | None,
        *,
        receipt_id: str | None = None,
        body_hash: str | None = None,
        route: str | None = None,
        sent_at: float | None = None,
    ) -> bool:
        """`check_reply` as a yes or no: anything but "failed" is a yes."""
        return (
            self.check_reply(response_id, receipt_id=receipt_id, body_hash=body_hash, route=route,
                             sent_at=sent_at)
            != "failed"
        )

    def check_reply(
        self,
        response_id: str | None,
        *,
        receipt_id: str | None = None,
        body_hash: str | None = None,
        route: str | None = None,
        sent_at: float | None = None,
    ) -> Mark:
        """`check`'s mark alone, nothing more looked up: the word, which says too whether the
        reply's receipt was read and held (`Mark.receipt`)."""
        found = self.check(response_id, receipt_id=receipt_id, body_hash=body_hash, route=route,
                           sent_at=sent_at)
        return Mark(found.mark, found.receipt)

    def check(
        self,
        response_id: str | None,
        *,
        receipt_id: str | None = None,
        body_hash: str | None = None,
        route: str | None = None,
        sent_at: float | None = None,
        name_upstream: bool = False,
    ) -> ReplyCheck:
        """Was this reply the attested enclave's, as received? "verified":
        signed by a key the quote binds (`signers`), for these exact bytes, its
        receipt (where read) holding; "signed": signed by it, the bytes not
        comparable (a stream nano-gpt rebuilds, or none); "failed". Raises
        ProviderError when the check couldn't be made (the reply is then
        "unchecked"), or when the provider signs no such reply (`signs`: the
        reply is "unsigned").

        nano-gpt's record for a reply (Nov 2026: RedPill's signed receipts,
        looked up by the receipt id its headers name, or the reply's id):

        - `text`, "sha256(request):sha256(response)" as the gateway hashed
          them, signed (EIP-191) by the signing key the quote bound, or by a
          key of the keyset the gateway's quote binds (`_attest_gateway`);
        - the response's hash is the hash of the exact bytes a stream carried
          (`body_hash`, llm/client.py), except where nano-gpt rebuilds a model's
          stream (`REBUILT_STREAMS`) or a reply wasn't streamed;
        - the receipt, signed (Ed25519) by a key of the attested keyset
          (`_take_keyset`), naming the same two hashes, and that its upstream
          was verified, as nano-gpt now requires, served after `sent_at` (when the
          request went, time.time()) and not after now, RECEIPT_CLOCK_SKEW_SECONDS
          either way: so it is this request's, not an earlier exchange's handed back
          (one served outside that is "failed", and attested again; with no
          `sent_at` a receipt can't be dated, and the reply is unchecked). For a model attested through
          RedPill's gateway alone (`receipt_required`), a record with no
          receipt read under the attested keys (none came, or the keys weren't
          kept) raises: the reply is "unchecked", never verified on the
          gateway's signature alone. A model attested itself needs none: its
          own key signed the record.

        A stream's receipt is complete just after it ends: a lookup that
        finds none yet is tried again for a while.

        `name_upstream` (Settings → Model, off by default): for a reply that
        checks out with its receipt read under the attested keys, who ran its
        model too (`served_by`: a lookup on api.redpill.ai). It never changes
        the mark.

        With the mark, whether the reply's receipt was read under the attested
        keys and held (`ReplyCheck.receipt`): the mark's tooltip says so, since
        a model attested itself is verified without one."""
        with self._in_use():
            return self._check(response_id, receipt_id, body_hash, route, sent_at, name_upstream)

    def _check(
        self,
        response_id: str | None,
        receipt_id: str | None,
        body_hash: str | None,
        route: str | None,
        sent_at: float | None,
        name_upstream: bool,
    ) -> ReplyCheck:
        """`check`, with the http client held open (`_in_use`)."""
        lookup = receipt_id or response_id
        if not lookup:
            raise ProviderError("the reply carried no id to check")
        if not self.signs(receipt_id):
            raise ProviderError("this model's provider signs no replies")
        body = self._signature(lookup, route, wait=receipt_id is not None)
        text, signature = body.get("text"), body.get("signature")
        if not isinstance(text, str) or not isinstance(signature, str):
            raise ProviderError("the signature reply held no text or signature")
        try:
            signer = recover_personal(text, signature)
        except ValueError:
            return ReplyCheck("failed")
        if signer.lower() not in self.signers:
            return ReplyCheck("failed")
        request_hash, _colon, response_hash = text.partition(":")
        compared = bool(body_hash) and self.model not in REBUILT_STREAMS
        if compared and f"sha256:{response_hash.lower()}" != body_hash:
            return ReplyCheck("failed")
        receipt = body.get("receipt")
        checked = isinstance(receipt, dict) and self.keyset is not None
        if checked and not self._receipt_holds(receipt, request_hash, response_hash, sent_at):
            return ReplyCheck("failed")
        if self.receipt_required and not checked:
            # Attested through the gateway alone, the gateway's signature says
            # only that the reply passed through it: the receipt is its word
            # that the model's own enclave answered, and without one that holds
            # under the attested keys, that much wasn't checked.
            raise ProviderError(
                "the reply came with no receipt to say the model's enclave answered"
            )
        mark = "verified" if compared else "signed"
        if not name_upstream:
            return ReplyCheck(mark, receipt=checked)
        if not checked:
            # A session named by a receipt that wasn't read under the attested keys is anyone's word.
            return ReplyCheck(mark, TeeUpstream(note="its receipt wasn't read under the attested keys"))
        try:
            return ReplyCheck(mark, self.served_by(receipt), True)
        except Exception as exc:  # noqa: BLE001 - whatever kept the provider from being named, the mark stands
            return ReplyCheck(mark, TeeUpstream(note=f"RedPill's record couldn't be read ({type(exc).__name__})"), True)

    def served_by(self, receipt: dict[str, Any]) -> TeeUpstream:
        """Who ran the model of a reply whose receipt held (`check`), by RedPill's public record of
        its gateway's session with that machine: named by the receipt, fetched once a session
        (`_session_record`). Not for a model Chutes serves: each of its instances has a session of
        its own, megabytes each. What the record says is RedPill's word; anything that kept it from
        being read is a note, never a failure. (SealedLore 44e145d.)"""
        event = next(
            (e for e in receipt.get("event_log") or []
             if isinstance(e, dict) and e.get("type") == "upstream.verified"),
            {},
        )
        model = relay_said(str(event.get("model_id") or ""), 80)
        if self.instances:
            return TeeUpstream(model=model, note=("not looked up for a model Chutes serves: each of its instances "
                                                  "has a record of its own, megabytes each"))
        session = event.get("session_id")
        if not (isinstance(session, str) and re.fullmatch(r"[0-9a-f]{64}", session)):
            return TeeUpstream(model=model, note="its receipt names no session")
        with _records_lock:
            asked = session not in _records
        try:
            record = _session_record(self._client, session)
        except ProviderError as exc:
            return TeeUpstream(model=model, note=str(exc), session=session, asked=asked)
        served = receipt.get("served_at")
        if not (_integer(served) and record.established <= served <= record.expires):
            return TeeUpstream(model=model, note="it was served outside the session its receipt names",
                               session=session, asked=asked)
        return TeeUpstream(name=record.name or "an unnamed provider", verifier=record.verifier, scope=record.scope,
                           gpus=record.gpus, model=model, session=session, asked=asked)

    def signs(self, receipt_id: str | None = None) -> bool:
        """Whether the attested provider signs a reply that named this receipt
        (or none), so that a record not found leaves it "unchecked" rather than
        "unsigned". Per-instance providers (Chutes) sign no replies: nano-gpt
        answers "TEE signature is not available for this model", and every
        instance that could answer was attested before sending instead. Only a
        reply RedPill's gateway answered names a receipt (nano-gpt, Nov 10
        2026): one checked against the gateway's keys, where it was attested.

        A model attested through the gateway alone signs, whatever its reply
        named: the gateway signs every record. Its reply with no receipt that
        holds is then "unchecked" (`check_reply` raises), never "unsigned":
        that mark says every instance that could answer was attested before
        sending, and here none of the model's own was."""
        return bool(self.signers) and not (self.instances and receipt_id is None)

    def _signature(self, lookup: str, route: str | None, *, wait: bool) -> dict[str, Any]:
        """The reply's record; for a reply that named its receipt, tried again
        while it isn't ready (404, 502, 503). One that named none is looked up
        once: live, TEE/gemma-4-31b-it's replies have no receipt to wait for."""
        params = {"model": self.model}
        path = f"/tee/signature/{quote(lookup, safe='')}"
        deadline = time.monotonic() + (RECEIPT_WAIT_SECONDS if wait else 0)
        while True:
            try:
                return self._get(path, params, route=route)
            except ProviderError as exc:
                # By the status, never the words: an error that merely says "404" (a receipt id,
                # the gateway's own message) isn't one (SealedLore 1a61096).
                ready_later = exc.status_code in (404, 502, 503)
                if not ready_later or time.monotonic() >= deadline:
                    # Live: some TEE/ models' providers keep no signature for a reply.
                    raise ProviderError("the provider has no signature for this reply") from exc
            time.sleep(RECEIPT_RETRY_SECONDS)

    def _receipt_holds(
        self,
        receipt: dict[str, Any],
        request_hash: str,
        response_hash: str,
        sent_at: float | None,
    ) -> bool:
        """The receipt was signed by a key of the attested keyset, under that
        keyset, for this exchange (the hashes the attested key signed), its
        upstream was verified, as nano-gpt requires, and it was served for this
        request, after it was sent and not after now (RECEIPT_CLOCK_SKEW_SECONDS
        either way). Raises ProviderError when that can't be told."""
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        assert self.keyset is not None
        if receipt.get("workload_keyset_digest") != self.keyset_digest:
            # The gateway renews its keys now and then: not a failed reply.
            raise ProviderError("the gateway's keys changed since it was attested")
        served = receipt.get("served_at")
        if receipt.get("api_version") != "aci/1" or not _integer(served):
            return False
        if served >= self.keyset.get("not_after", 0):
            return False
        entry = next(
            (
                key
                for key in self.keyset.get("receipt_signing_keys") or []
                if isinstance(key, dict) and key.get("key_id") == receipt.get("key_id")
            ),
            None,
        )
        if entry is None or entry.get("algo") != "ed25519":
            return False
        unsigned = {key: value for key, value in receipt.items() if key != "signature"}
        try:
            Ed25519PublicKey.from_public_bytes(_hex(entry.get("public_key"))).verify(
                _hex(receipt.get("signature")), _canonical(unsigned)
            )
        except (InvalidSignature, ValueError, TypeError):
            return False
        events: dict[str, dict[str, Any]] = {}
        for event in receipt.get("event_log") or []:
            if isinstance(event, dict):
                events.setdefault(str(event.get("type")), event)
        hashes = (
            events.get("request.received", {}).get("body_hash"),
            events.get("response.returned", {}).get("body_hash"),
        )
        if hashes != (f"sha256:{request_hash.lower()}", f"sha256:{response_hash.lower()}"):
            return False
        upstream = events.get("upstream.verified", {})
        if upstream.get("result") != "verified" or upstream.get("required") is not True:
            return False
        if sent_at is None:
            # Nothing dates the record's text, and the receipt can't be held to a request whose
            # time isn't known.
            raise ProviderError("when this reply's request was sent isn't known")
        # An exchange the attested gateway says it served before this request went (or long after
        # now) isn't this request's: a relay handing back an earlier signed stream, its bytes and
        # hashes all as they were.
        return sent_at - RECEIPT_CLOCK_SKEW_SECONDS <= served <= self._wall() + RECEIPT_CLOCK_SKEW_SECONDS
