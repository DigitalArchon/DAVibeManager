"""TEE models on nano-gpt: attestation before anything is sent, and a check of every reply. Ported
from SealedLore (its providers/tee.py, Sept 2026, its reply receipts, Nov 2026, and the gateway's own
report, Nov 10 2026); the checks are the same.

What the attestation is of (looked into Nov 2026): for most of nano-gpt's TEE/ models it is RedPill's
gateway (its "aci/1" report, relayed by nano-gpt), which passes each request on to the model's host
(Phala, NEAR AI, Tinfoil, Chutes…). Its quote is the gateway VM's; the GPU evidence is the upstream
node's, made with our nonce but not bound to the gateway's quote; that the model itself runs in an
enclave isn't in the report. RedPill states that per reply, in a signed receipt (`check_reply`
reads it where nano-gpt keeps one), so such an attestation is "partial" here ("the model's own
enclave unchecked"), and the user is told. For a model sealed end to end, use a private/ one
(llm/private_mode.py).

nano-gpt's `TEE/*` models run inside a trusted execution environment. Two
calls let a client check that (docs.nano-gpt.com/api-reference/tee-verification):

- `GET {base}/tee/attestation?model=&nonce=` returns the enclave's
  `signing_address`, an Intel TDX quote (`intel_quote`) and NVIDIA GPU evidence
  (`nvidia_payload`), or, for a model Chutes answers, each instance's evidence.
  The quote's report data, read from its own bytes, must be the signing
  address, zero padding, then our nonce. With `&report=aci` (Nov 10 2026),
  RedPill's gateway's own report: its quote binds the gateway's whole keyset,
  the receipt key and the record-signing keys, to our nonce
  (`_attest_gateway`). Both are asked for, each with its own nonce. The
  quote is verified up to Intel's pinned root, with Intel's revocation lists
  and TCB ratings (llm/dcap.py). The GPU evidence goes to NVIDIA's
  attestation service, and NVIDIA's signed answer must be for our nonce and
  pass (llm/nras.py). `attest` refuses (`TeeRefused`) or returns a "full" or
  "partial" attestation: see its docstring.
- `GET {base}/tee/signature/{receipt or completion id}?model=` returns a
  `text` and an EIP-191 `signature`; the signer recovered from them must be
  an attested key's address (llm/ethsig.py). Since Nov 2026 (RedPill's signed
  receipts; nano-gpt's fix of the lookup, which had answered 404) the text's
  `sha256(response)` is the hash of the exact bytes a stream carried, and the
  answer carries RedPill's receipt too (`check_reply`). The gateway checks
  every TEE reply so, once it has passed on (gateway.py).

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
`private/` model (llm/private_mode.py). Every TEE reply is read as a stream,
its bytes hashed, so nano-gpt's exact mode for whole replies
(`X-NanoGPT-TEE-Response`) isn't needed.

Which machine is attested (`Attestation.attested`, `what_was_attested`, SealedLore's, Nov 11 2026):
for every model RedPill serves, its gateway (live: the plain report's quote is the gateway's image,
its signing key the gateway's), which passes requests on to the machine running the model; that
machine is the gateway's word in the receipt (`upstream.verified`). For a model Chutes serves, each
instance it lists. The GPU evidence nano-gpt's report carries is for our nonce but not in the
quote (`GPUS_LOOSE`).

Who ran a reply's model (SealedLore's, Nov 11 2026): the receipt names the gateway's session with
that machine by the sha256 of RedPill's public record of it (api.redpill.ai/v1/aci/sessions/{id}),
which says which provider it is. It is fetched only when the user asks for it (Settings, off by
default: `check` with `name_upstream`, `served_by`), since it goes to api.redpill.ai directly, once
a session, and never for a model Chutes serves: a Chutes instance has a session of its own (3.4 MB
for TEE/deepseek-v3.2) and replies are spread over the instances, so it would be megabytes nearly
every message (the author: not every message).
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
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from ..netpolicy import check_key, check_url, scrubbed, shown
from . import dcap, nras
from .ethsig import keccak256, recover_personal
from .private_mode import relay_said
from .secure_http import ProviderError, make_client

NRAS_URL = "https://nras.attestation.nvidia.com/v3/attest/gpu"
TIMEOUT_SECONDS = 30.0
# Chutes' evidence can take about a minute (nano-gpt, Nov 10 2026; SealedLore measured 25 s for
# TEE/gemma4-31b:thinking's 40 instances).
ATTESTATION_TIMEOUT_SECONDS = 90.0
# A stream's receipt is complete just after the stream ends (nano-gpt's own
# example waits up to about 20 seconds).
RECEIPT_WAIT_SECONDS = 20.0
RECEIPT_RETRY_SECONDS = 2.0
# Models whose streams nano-gpt rebuilds from the upstream's, so their bytes
# never match the receipt's hash (nano-gpt, Nov 2026).
REBUILT_STREAMS = frozenset({"TEE/gemma-4-31b-it"})
# A shortfall (SealedLore's): the quote binds the key that signs each reply's
# record, not the receipt keys around it (nano-gpt has no gateway report for the model).
RECEIPT_KEYS_LOOSE = "receipt keys not in the quote"
# A shortfall too (SealedLore's, Nov 11 2026): NVIDIA vouched for GPU evidence made with our nonce, but
# the quote of the machine attested doesn't commit to it (nano-gpt's report: the signing address and our
# nonce only), so the GPUs may be another machine's, the model's upstream say, relayed. A Chutes
# instance's quote binds its GPU evidence's nonce, so its GPUs are its own.
GPUS_LOOSE = "GPUs not tied to the quote"
# A shortfall: RedPill's gateway is attested, not the model's host behind it.
MODEL_ENCLAVE_UNCHECKED = "the model's own enclave unchecked (RedPill's gateway)"
# A shortfall: a model Chutes answers first, which RedPill's gateway answers now and then, attested
# while nano-gpt had no gateway report for a reason but that RedPill doesn't serve it (a rate limit,
# an outage): whether its gateway may answer, and its keys, aren't known (`_attest_instances`).
GATEWAY_UNCHECKED = "RedPill's gateway unchecked"
# RedPill's public records of its gateway's sessions with the machines that run the models (the user's
# choice, off by default: `served_by`). Each receipt's `upstream.verified` names its session by the
# sha256 of the record's RFC 8785 JSON, so the attested gateway's signature pins it whoever serves it.
# No key goes with it.
SESSION_RECORDS = "https://api.redpill.ai/v1/aci/sessions/"
# A record past this is never read: a Chutes instance's is megabytes (3.4 MB for TEE/deepseek-v3.2,
# Nov 11 2026), and its replies spread over instances with a session each, so it would be megabytes
# nearly every message (the author: not that). Live, the others were 3 KB-0.3 MB, one an hour a model.
SESSION_RECORD_MAX_BYTES = 1_000_000
# Records already read, by session id (content-addressed, so the same for every client): a session
# serves every reply to its provider for an hour.
SESSION_RECORDS_KEPT = 64
_records: dict[str, _Record] = {}
_records_lock = threading.Lock()
# RedPill's names for its upstreams as the app shows them (`upstream_label`); any other is shown as
# RedPill writes it.
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
    # requests on; "instances", each instance the provider listed; "enclave", the one whose key signs
    # the replies, not shown to be either. "" before Nov 11 2026.
    attested: str = ""

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

    def to_dict(self) -> dict:
        return {**asdict(self), "summary": self.summary}


@dataclass(frozen=True)
class TeeUpstream:
    """Who ran a TEE reply's model, by RedPill's record of its gateway's session with that machine
    (`served_by`; the user's choice, off by default). The record is RedPill's word, pinned by the
    receipt the attested gateway signed; nothing in it is checked by this app (SealedLore's
    models/private.TeeUpstream)."""

    # RedPill's name for the provider ("tinfoil", "phala-244"); "" when the lookup was made and named
    # none, `note` saying why.
    name: str = ""
    # The verifier RedPill's gateway checked that machine with, what it vouched for ("model_instance",
    # "router", "near-ai-gateway"), and what RedPill says of its GPUs ("asserted", "unknown").
    verifier: str = ""
    scope: str = ""
    gpus: str = ""
    # The model id the receipt names upstream ("gemma4-31b").
    model: str = ""
    note: str = ""


@dataclass(frozen=True)
class ReplyCheck:
    """What `TeeClient.check` found of a reply: its mark ("verified", "signed", "failed"), and who ran its
    model, when asked to look."""

    mark: str
    upstream: TeeUpstream | None = None


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
    """The provider as a reply's mark names it: "Tinfoil" for "tinfoil", "Phala" for "phala-244", else as
    RedPill writes it."""
    name = upstream.name
    return _UPSTREAM_LABELS.get(re.sub(r"-\d+$", "", name), name)


def upstream_words(upstream: TeeUpstream) -> str:
    """A reply's provider, said plainly, for its mark's tooltip: whose word it is, and what it doesn't
    prove."""
    if not upstream.name:
        return f"The provider that ran it wasn't named: {upstream.note}."
    scope = upstream.scope
    what = (
        "the machine that ran the model"
        if scope == "model_instance"
        else "its router, which passes requests on to the model"
        if scope == "router"
        else "its gateway, which passes requests on to the model"
        if "gateway" in scope
        else "it"
    )
    gpus = {
        "asserted": "RedPill's verifier checked its GPUs",
        "unknown": "RedPill's record has no GPU attestation",
    }.get(upstream.gpus, "")
    model = f" (as {upstream.model})" if upstream.model else ""
    return (
        f"Run by {upstream_label(upstream)}{model}: RedPill's record of its gateway's session says its "
        f"verifier ({upstream.verifier or 'unnamed'}) checked {what}"
        + (f"; {gpus}" if gpus else "")
        + ". That is RedPill's word, fetched from api.redpill.ai and matched to the receipt the attested "
        "gateway signed; this app doesn't check that machine."
    )


def _session_record(client: httpx.Client, session_id: str) -> _Record:
    """RedPill's record of one session, read once a process: from api.redpill.ai, with no key, at most
    SESSION_RECORD_MAX_BYTES read a piece at a time, and only if its sha256 is the id the receipt named.
    By the TEE client's own httpx client, as its other fetches (Intel's, NVIDIA's): the environment's
    proxy, and no redirect followed or to anywhere insecure (llm/secure_http.py). Raises ProviderError,
    in words a tooltip can carry, for what kept it from being read."""
    with _records_lock:
        if session_id in _records:
            return _records[session_id]
    body = bytearray()
    try:
        with client.stream("GET", SESSION_RECORDS + session_id, timeout=TIMEOUT_SECONDS) as response:
            if response.status_code != 200:
                raise ProviderError(f"api.redpill.ai answered HTTP {response.status_code}")
            length = response.headers.get("content-length", "")
            if length.isdigit() and int(length) > SESSION_RECORD_MAX_BYTES:
                raise ProviderError(
                    f"its record is {int(length) // 1000:,} KB, more than is read for one reply"
                )
            for chunk in response.iter_bytes():
                body += chunk
                if len(body) > SESSION_RECORD_MAX_BYTES:
                    raise ProviderError("its record is more than is read for one reply")
    except httpx.HTTPError as exc:
        raise ProviderError(f"api.redpill.ai couldn't be reached ({type(exc).__name__})") from exc
    try:
        record = json.loads(bytes(body))
        named = isinstance(record, dict) and hashlib.sha256(_canonical(record)).hexdigest() == session_id
    except (ValueError, RecursionError) as exc:      # nested past what can be read: never the mark's concern
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
        established=established if isinstance(established, int) else 0,
        expires=expires if isinstance(expires, int) else 0,
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
    """The address of an uncompressed secp256k1 public key (04…), lowercase."""
    try:
        key = _hex(value)
    except ValueError:
        return None
    if len(key) != 65 or key[0] != 4:
        return None
    return "0x" + keccak256(key[1:])[-20:].hex()


def _json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return None
    return value


def _jwt_claims(value: Any) -> list[dict[str, Any]]:
    """Every JWT's payload found in a JSON value, in order."""
    found: list[dict[str, Any]] = []
    if isinstance(value, str) and value.count(".") == 2:
        part = value.split(".")[1]
        try:
            claims = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        except (ValueError, binascii.Error):
            return found
        if isinstance(claims, dict):
            found.append(claims)
    elif isinstance(value, list):
        for item in value:
            found.extend(_jwt_claims(item))
    elif isinstance(value, dict):
        for item in value.values():
            found.extend(_jwt_claims(item))
    return found


def is_tee(model: str) -> bool:
    """A model that runs in a trusted execution environment: nano-gpt's
    `TEE/*` (attested and signed) or `private/*` (end-to-end encrypted)."""
    return model.startswith(("TEE/", "private/"))


def is_private_mode(model: str) -> bool:
    """nano-gpt's Private Mode: end-to-end encrypted to an attested enclave
    (llm/private_mode.py). Never sent any other way."""
    return model.startswith("private/")


def what_was_attested(attestation: Attestation) -> str:
    """What an attestation that held was of, and what it leaves to someone's word, plainly, for
    wherever the attestation is shown (SealedLore's, Nov 11 2026; the author: "always make clear to
    the user what is actually happening and if it is properly attested or not"). Live, Nov 11 2026:
    every model RedPill serves is attested as its gateway, which passes requests to the model's own
    provider (Phala, Fortanix, NEAR AI, 0G, Tinfoil's router or Chutes, by RedPill's session
    records); a model Chutes serves itself, as its instances."""
    clear = (
        " What you send passes NanoGPT's servers in the clear on the way; a private model is "
        "end-to-end encrypted instead."
    )
    if attestation.attested == "gateway":
        return (
            "Attested: RedPill's TEE gateway, which NanoGPT sends this model's requests through and "
            "which passes them on to the machine that runs the model. That machine isn't attested by "
            "this app: that it is a verified TEE is the gateway's word, in each reply's signed receipt."
            + clear
        )
    if attestation.attested == "instances":
        count = attestation.instances
        listed = f"each of the {count} instances" if count > 1 else "the instance"
        return (
            f"Attested: {listed} this model's provider listed. They sign no replies, so nothing shows "
            "which machine answered a request: NanoGPT routes each one, and a model may be served "
            "elsewhere when its provider is busy." + clear
        )
    if attestation.attested == "enclave":
        return (
            "Attested: the enclave whose key signs this model's replies. Whether that machine runs the "
            "model itself or passes requests on isn't shown." + clear
        )
    return ""


def _bases(base_url: str) -> list[str]:
    """Where the TEE endpoints may live: the docs give the path three ways."""
    base = base_url.rstrip("/")
    parsed = urlparse(base)
    root = f"{parsed.scheme}://{parsed.netloc}"
    found = [base, f"{root}/api/v1", f"{root}/v1"]
    return list(dict.fromkeys(found))


def _error_text(response: httpx.Response) -> str:
    """The provider's message from an error response, or "": one short line, without what a reader
    can't see (private_mode.relay_said). Nothing vouches for it, and it is shown, logged and told the
    assistant as the reason its request was refused."""
    try:
        body = response.json()
    except ValueError:
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
        self, attested: str, *, signing_address: str | None = None, instances: int = 0
    ) -> Attestation:
        return Attestation(
            verified=True,
            level="partial" if self.shortfalls else "full",
            shortfalls=list(self.shortfalls),
            signing_address=signing_address,
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
    # each reply's record (the gateway's e2ee keys, live Nov 2026).
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
    ) -> None:
        check_url(base_url, "The provider's base URL")      # https, or a local address: the key goes there
        check_key(api_key, urlparse(base_url).hostname or "the provider")
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
        # Attested through the gateway alone (`_attest_gateway_alone`): a reply
        # is verified only with a receipt that holds, the gateway's word that
        # the model's own enclave answered it.
        self.receipt_required = False
        # The receipt keys, when tied to the attested quote (`_take_keyset`).
        self.keyset: dict[str, Any] | None = None
        self.keyset_digest: str | None = None
        self._base: str | None = None
        # The two verifiers, replaceable so tests can stand in for Intel and NVIDIA.
        self._intel = intel or dcap.verify
        self._nvidia = nvidia or nras.verify

    def close(self) -> None:
        if self._owns:
            self._client.close()

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
            # nano-gpt names a route on a reply now and then: its checks name it too. Only
            # a reply's: an attestation is made before a request, when no reply has named
            # one, and a route lasts an hour (an expired one makes attestation 400: nano-gpt,
            # Nov 10 2026), so attesting with an earlier reply's route could only refuse.
            headers["X-TEE-Verification-Route"] = route
        last: str = ""
        for base in [self._base] if self._base else _bases(self.base_url):
            try:
                response = self._client.get(
                    f"{base}{path}",
                    params=params,
                    headers=headers,
                    **({"timeout": timeout} if timeout is not None else {}),
                )
            except httpx.HTTPError as exc:
                last = scrubbed(exc)
                continue
            if response.status_code == 404:
                last = f"{shown(base + path)}: 404"
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
                body = response.json()
            except ValueError as exc:
                raise ProviderError(f"{shown(base + path)} returned a non-JSON body") from exc
            if not isinstance(body, dict):
                raise ProviderError(f"{shown(base + path)} returned {type(body).__name__}")
            self._base = base
            return body
        raise ProviderError(f"no TEE endpoint answered ({last})")

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
        gateway's whole keyset to our nonce. Where nano-gpt has one: a signing key
        in that keyset has its receipt keys bound too; a model whose own report
        was relayed for a nonce not ours, or timed out, is attested through the
        gateway that answers it (`_attest_gateway_alone`); a Chutes model's
        replies that RedPill answers instead are checked against its keys.

        Refuses (`TeeRefused`, and nothing may be sent) when an enclave can't be
        trusted: no attestation, a quote that doesn't bind our nonce (directly, or
        by a key the quote binds), a quote Intel's chain doesn't vouch for (forged,
        revoked, a debug TD, a TCB Intel revoked or never listed), GPU evidence
        whose NVIDIA verdict is unsigned, stale, for another nonce or negative
        (llm/dcap.py, llm/nras.py), any instance that failed to attest
        (a request could be routed to it), evidence relayed for a nonce the
        relay chose (RedPill: replayable) with no gateway report to stand in, a
        gateway report for another nonce, or a gateway's keys past the time its
        keyset holds them until.

        What merely couldn't be checked (Intel's collateral or NVIDIA's service out
        of reach, no GPU evidence offered) or isn't current (any Intel TCB status
        but UpToDate) makes the attestation "partial", each reason in `shortfalls`.

        Until Sept 2026 a nonce that merely came back in nano-gpt's JSON counted,
        the report data was read from nano-gpt's copy, and neither Intel's nor
        NVIDIA's signatures were checked. Anything can echo a string.
        """
        self.signing_address = None
        self.signers = frozenset()
        self.keyset = self.keyset_digest = None
        self.instances = False
        self.receipt_required = False
        gateway, unheard = self._attest_gateway()
        try:
            body, nonce = self._fetch_attestation()
        except ProviderError as exc:
            if gateway is not None and exc.status_code == 504:
                # nano-gpt's `tee_attestation_upstream_timeout`, asked twice (SealedLore, live,
                # Nov 10 2026: TEE/qwen3.6-27b). Only that: SealedLore lets the gateway stand in
                # for any failure here, and a rate limit (429, seen live) or an outage would
                # then send a model Chutes answers first to instances not attested this time.
                return self._attest_gateway_alone(gateway, "its own attestation timed out")
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
                f"({body.get('attestation_type') or 'unnamed'}), was {why}, so it can't "
                "show the enclave is live for this request"
            )
        if body.get("signing_address") or body.get("intel_quote"):
            return self._attest_signing_key(body, nonce, gateway)
        if body.get("error"):
            raise TeeRefused(f"nano-gpt couldn't attest {self.model}: {relay_said(str(body['error']))}")
        raise TeeRefused(
            f"{self.model}'s attestation is in a shape this app doesn't recognise "
            f"(it holds {', '.join(sorted(body)) or 'nothing'})"
        )

    def _fetch_attestation(self, *, aci: bool = False) -> tuple[dict[str, Any], str]:
        """nano-gpt's attestation for a fresh nonce, and the nonce. A 504 (the
        provider's evidence took too long: `tee_attestation_upstream_timeout`)
        is asked once more with a new nonce, as nano-gpt says to."""
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
        (an outage, a rate limit: `_attest_instances`), else "".

        The quote's report data is the SHA-256 of RedPill's attestation
        statement, the gateway's whole keyset and our nonce, zero padded
        (`_statement`): the hardware binds the receipt key and the keys that
        sign each reply's record, which nano-gpt's other report doesn't (it
        binds one signing key, the keyset published beside it). Every model
        RedPill serves is answered by the same gateway image (SealedLore, live:
        14 of 14 quotes alike, plain and aci). Refuses a report in RedPill's
        shape that doesn't bind our nonce, Intel doesn't vouch for, or whose
        keys are past their time."""
        try:
            body, nonce = self._fetch_attestation(aci=True)
        except ProviderError as exc:
            return None, "" if exc.status_code == 400 else str(exc)[:200]
        report = body.get("attestation") if body.get("api_version") == "aci/1" else None
        evidence = report.get("evidence") if isinstance(report, dict) else None
        keyset = report.get("workload_keyset") if isinstance(report, dict) else None
        if not (isinstance(evidence, dict) and isinstance(keyset, dict) and evidence.get("quote")):
            return None, ""
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
        """Keys the gateway's keyset holds only until a time now past are refused: what was
        attested is keys no longer in force. (SealedLore names them short; here, as for RedPill's
        gateway before, they are refused.) One that names no such time isn't used for the
        receipts, and falls short (`_take_keyset`)."""
        expires = keyset.get("not_after") if keyset is not None else None
        if isinstance(expires, (int, float)) and expires < time.time():
            raise TeeRefused(f"{self.model}'s attested keys expired on {datetime.fromtimestamp(expires, UTC):%Y-%m-%d}")

    def _attest_gateway_alone(self, gateway: _Gateway, why: str) -> Attestation:
        """The gateway, attested for our nonce, stands for a model whose own
        attestation was relayed for a nonce not ours or timed out (SealedLore, live,
        Nov 10 2026: TEE/deepseek-v3.2 and TEE/qwen3.6-27b, a 504).
        Its replies are signed by the gateway's bound keys and carry its receipts;
        the model's own enclave and GPUs are then the gateway's word in each
        receipt (`upstream.verified`), not checked here: so it falls short."""
        check = _Checks(f"{why}: the gateway that answers it is attested instead")
        check.merge(gateway.check)
        check.fall_short("no GPU evidence")
        check.fall_short(MODEL_ENCLAVE_UNCHECKED)
        check.note(
            "its own enclave isn't attested here: each reply's receipt carries the "
            "gateway's word that its upstream was verified"
        )
        self.signers = gateway.signers
        self.receipt_required = True
        self._take_keyset(gateway.keyset, "the quote binds its receipt keys", check)
        return check.attestation("gateway")

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
        # The gateway, when its report binds a keyset this key is in: the key is the gateway's.
        bound = gateway if gateway is not None and address.lower() in gateway.signers else None
        # The machine whose key signs the replies (`Attestation.attested`): RedPill's gateway when the
        # key is one of the gateway's own (its keyset), else not known to be.
        attested = "enclave"
        if (
            report_data[:20] == bytes.fromhex(address[2:])
            and not any(report_data[20:32])
            and report_data[32:] == bytes.fromhex(nonce)
        ):
            check = _Checks("the Intel TDX quote binds the signing key to our nonce")
            if bound is not None:
                # ... and so the receipt key is the hardware's too (nano-gpt's report=aci,
                # Nov 10 2026). Its keys sign records as this one does.
                check.merge(bound.check)
                keyset, signers = bound.keyset, bound.signers
                tie = "the gateway's quote binds its receipt keys, the signing key among them"
                attested = "gateway"
            else:
                tie = (
                    "its receipt keys are published beside the attested signing key"
                    if holds
                    else ""
                )
                # The receipts' word that the model was verified then rests on the
                # relay's JSON, not the hardware (nano-gpt, Nov 2026), and the same
                # with no keyset at all: said either way, so leaving it out never
                # reads better than sending it (SealedLore's, the author's call).
                check.fall_short(RECEIPT_KEYS_LOOSE)
                if gateway is not None:
                    check.note("the gateway's attested keys don't include the signing key")
        elif keyset is not None and holds and report_data == _statement(keyset, nonce):
            check = _Checks(
                "the Intel TDX quote binds the gateway's keys, its signing key among them, "
                "to our nonce"
            )
            tie = "the quote binds its receipt keys"
            attested = "gateway"
        else:
            raise TeeRefused(f"{self.model}'s attestation didn't bind its signing key to our nonce")
        self._refuse_expired(keyset)
        caps = body.get("service_capabilities") if isinstance(body.get("service_capabilities"), dict) else {}
        if bound is not None or body.get("api_version") == "aci/1" or caps.get("serving") == "aggregator":
            # RedPill's gateway (live, Nov 2026: the same key since Sept): it passes requests on to the model's
            # host. Its quote is the gateway's; the GPU evidence is an upstream node's, made with our nonce but
            # not bound to that quote; that the model itself runs in an enclave isn't shown here (RedPill says it
            # in each reply's signed receipt, read where nano-gpt keeps one: check_reply).
            check.fall_short(MODEL_ENCLAVE_UNCHECKED)
            check.note("this is RedPill's gateway, which passes each request on to the model's host: the gateway's "
                       "quote and the GPUs' evidence are checked, not that the model itself runs in an enclave")
        self._check_quote(raw, check)
        payload = _json(body.get("nvidia_payload"))
        payload = payload if isinstance(payload, dict) else None
        self._check_gpus(payload, nonce, check, "this request's nonce")
        if payload is not None and payload.get("evidence_list"):
            # The quote's report data is the signing key and our nonce (or the keyset and our nonce):
            # nothing in it commits to the GPU evidence.
            check.fall_short(GPUS_LOOSE)
            check.note(
                "the quote doesn't commit to the GPU evidence, so the GPUs may be another machine's"
            )
        self.signing_address = address
        self.signers = signers
        self._take_keyset(keyset if tie else None, tie, check)
        return check.attestation(attested, signing_address=address)

    def _take_keyset(self, keyset: dict[str, Any] | None, tie: str, check: _Checks) -> None:
        """The gateway's receipt-signing keys (RedPill's aci/1 `workload_keyset`),
        kept for the receipts (`check_reply`) only when tied to the quote: it
        commits to them (RedPill's statement, or the gateway's report=aci), or
        they are published with the signing key it binds (nano-gpt's other
        report). The second is the weaker tie: the quote binds that key, not
        the keyset around it. A keyset tied neither way, or expired, is not
        used, and receipts go unread."""
        self.keyset = self.keyset_digest = None
        if keyset is None:
            return
        not_after = keyset.get("not_after")
        if not isinstance(not_after, int) or not_after <= time.time():
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
        short as any the gateway answers does (`MODEL_ENCLAVE_UNCHECKED`; DA
        Assistant's reading too; SealedLore counts it whole). Where nano-gpt had
        no gateway report for a reason but that RedPill doesn't serve the model
        (`unheard`: a rate limit, an outage), whether the gateway may answer isn't
        known: that falls short too (`GATEWAY_UNCHECKED`), so an outage never
        reads better than the report would.
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
        check.fall_short(MODEL_ENCLAVE_UNCHECKED)
        check.note(
            "RedPill's gateway answers it instead now and then, and passes the request on to a host "
            "of its own: such a reply is checked against the gateway's attested keys, and its host is "
            "the gateway's word in its receipt, not attested here"
        )
        self.signers = gateway.signers
        self._take_keyset(
            gateway.keyset,
            "a reply RedPill's gateway answers instead is checked against its attested keys",
            check,
        )
        attestation = check.attestation("instances", instances=len(instances))
        attestation.detail += "; the instances sign no replies, so their answers show as unsigned"
        return attestation

    def _check_instance(self, item: dict[str, Any], nonce: str) -> _Checks:
        name = str(item.get("instance_id") or "an instance")[:8]
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
            attested = json.loads(signed)
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
        """Intel's verification of one quote, into `check`. Refuses a bad quote."""
        try:
            intel = self._intel(raw, self._client)
        except dcap.DcapError as exc:
            raise TeeRefused(f"{self.model}'s Intel TDX quote failed verification: {exc}") from exc
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
            # Unchecked, but a verdict that says no is still believed.
            if not any(
                claims.get("x-nvidia-overall-att-result") is True for claims in _jwt_claims(answer)
            ):
                raise TeeRefused(f"NVIDIA rejected {self.model}'s GPU evidence") from exc
            check.fall_short("NVIDIA signature unchecked")
            check.note(f"{exc}, so NVIDIA's verdict is unchecked")
        except nras.NrasError as exc:
            raise TeeRefused(f"{self.model}'s GPU attestation failed: {exc}") from exc
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
            response = self._client.post(NRAS_URL, json=payload)
        except httpx.HTTPError:
            return None
        if response.status_code >= 500:
            return None
        if response.status_code >= 400:
            raise TeeRefused(
                f"NVIDIA rejected {self.model}'s GPU evidence (HTTP {response.status_code})"
            )
        try:
            return response.json()
        except ValueError:
            return None

    def verify_reply(
        self,
        response_id: str | None,
        *,
        receipt_id: str | None = None,
        body_hash: str | None = None,
        route: str | None = None,
    ) -> bool:
        """`check_reply` as a yes or no: anything but "failed" is a yes."""
        return (
            self.check_reply(response_id, receipt_id=receipt_id, body_hash=body_hash, route=route)
            != "failed"
        )

    def check_reply(
        self,
        response_id: str | None,
        *,
        receipt_id: str | None = None,
        body_hash: str | None = None,
        route: str | None = None,
    ) -> str:
        """`check`'s mark alone, nothing more looked up."""
        return self.check(response_id, receipt_id=receipt_id, body_hash=body_hash, route=route).mark

    def check(
        self,
        response_id: str | None,
        *,
        receipt_id: str | None = None,
        body_hash: str | None = None,
        route: str | None = None,
        name_upstream: bool = False,
    ) -> ReplyCheck:
        """Was this reply the attested enclave's, as received? "verified":
        signed by an attested key, for these exact bytes, its receipt (where
        read) holding; "signed": signed by it, the bytes not comparable (a
        stream nano-gpt rebuilds, or none); "failed". Raises ProviderError when
        the check couldn't be made (the reply is then "unchecked").

        nano-gpt's record for a reply (Nov 2026: RedPill's signed receipts,
        looked up by the receipt id its headers name, or the reply's id):

        - `text`, "sha256(request):sha256(response)" as the gateway hashed
          them, signed (EIP-191) by a key the quote binds (`signers`: the
          signing key, or every key of the gateway's bound keyset);
        - the response's hash is the hash of the exact bytes a stream carried
          (`body_hash`), except where nano-gpt rebuilds a model's stream
          (`REBUILT_STREAMS`) or a reply wasn't streamed;
        - the receipt, signed (Ed25519) by a key of the attested keyset
          (`_take_keyset`), naming the same two hashes, and that its upstream
          was verified, as nano-gpt now requires.

        A stream's receipt is complete just after it ends: a lookup that
        finds none yet is tried again for a while.

        `name_upstream`: for a reply that checks out with its receipt read,
        who ran its model too (`served_by`: a lookup on api.redpill.ai). It
        never changes the mark."""
        lookup = receipt_id or response_id
        if not lookup:
            raise ProviderError("the reply carried no id to check")
        if not self.signers or (self.instances and receipt_id is None):
            # Per-instance providers (Chutes) sign no replies: nano-gpt answers "TEE
            # signature is not available for this model". Every instance that
            # could answer was attested before sending instead. Only a reply
            # RedPill's gateway answered names a receipt (nano-gpt, Nov 10 2026).
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
        if checked and not self._receipt_holds(receipt, request_hash, response_hash):
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
            return ReplyCheck(mark)
        if not checked:
            # A session named by a receipt that wasn't read under the
            # attested keys is anyone's word.
            return ReplyCheck(
                mark, TeeUpstream(note="its receipt wasn't read under the attested keys")
            )
        return ReplyCheck(mark, self.served_by(receipt))

    def served_by(self, receipt: dict[str, Any]) -> TeeUpstream:
        """Who ran the model of a reply whose receipt held (`check`), by
        RedPill's public record of its gateway's session with that machine:
        named by the receipt, fetched once a session (`_session_record`).
        Not for a model Chutes serves: each of its instances has a session
        of its own, megabytes each. What the record says is RedPill's word;
        anything that kept it from being read is a note, never a failure."""
        event = next(
            (
                e
                for e in receipt.get("event_log") or []
                if isinstance(e, dict) and e.get("type") == "upstream.verified"
            ),
            {},
        )
        model = relay_said(str(event.get("model_id") or ""), 80)
        if self.instances:
            return TeeUpstream(
                model=model,
                note=(
                    "not looked up for a model Chutes serves: each of its instances has a "
                    "record of its own, megabytes each"
                ),
            )
        session = event.get("session_id")
        if not (isinstance(session, str) and re.fullmatch(r"[0-9a-f]{64}", session)):
            return TeeUpstream(model=model, note="its receipt names no session")
        try:
            record = _session_record(self._client, session)
        except ProviderError as exc:
            return TeeUpstream(model=model, note=str(exc))
        served = receipt.get("served_at")
        if not (isinstance(served, int) and record.established <= served <= record.expires):
            return TeeUpstream(
                model=model, note="it was served outside the session its receipt names"
            )
        return TeeUpstream(
            name=record.name or "an unnamed provider",
            verifier=record.verifier,
            scope=record.scope,
            gpus=record.gpus,
            model=model,
        )

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
                ready_later = exc.status_code in (502, 503) or "404" in str(exc)
                if not ready_later or time.monotonic() >= deadline:
                    # Live: some TEE/ models' providers keep no signature for a reply.
                    raise ProviderError("the provider has no signature for this reply") from exc
            time.sleep(RECEIPT_RETRY_SECONDS)

    def _receipt_holds(
        self, receipt: dict[str, Any], request_hash: str, response_hash: str
    ) -> bool:
        """The receipt was signed by a key of the attested keyset, under that
        keyset, for this exchange (the hashes the attested key signed), and
        its upstream was verified, as nano-gpt requires."""
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        assert self.keyset is not None
        if receipt.get("workload_keyset_digest") != self.keyset_digest:
            # The gateway renews its keys now and then: not a failed reply.
            raise ProviderError("the gateway's keys changed since it was attested")
        served = receipt.get("served_at")
        if receipt.get("api_version") != "aci/1" or not isinstance(served, int):
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
        return upstream.get("result") == "verified" and upstream.get("required") is True
