"""Which addresses the app may talk to, and how.

One rule for every client the app builds (model providers, attestation, the gateway's model
forwarder): https anywhere; plain http only to this machine or the local network. "Local" is
exactly localhost, loopback (127.0.0.0/8, ::1), the private ranges (10/8, 172.16/12,
192.168/16, fc00::/7), link-local, and `.local` names. A URL outside that set that isn't https
is refused with an explanation, never used and never rewritten.

The gateway's CONNECT proxy applies the opposite rule for the container: only addresses that
are globally routable (`is_global_ip`), and none of this computer's own or on its own networks
(`own_networks`: a global IPv6 address is routable, yet it is this computer, or a printer or NAS
next to it), so the builder can reach GitHub but not the user's LAN, router or this machine. An
IPv4 address carried inside an IPv6 one (NAT64, 6to4, Teredo) is judged as that IPv4 address.
"""

from __future__ import annotations

import fcntl
import ipaddress
import socket
import struct
from urllib.parse import urlparse

_PRIVATE_NETS = tuple(ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "::1/128",                                    # loopback
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",  # private
    "169.254.0.0/16", "fe80::/10",                                # link-local
))


class InsecureURL(ValueError):
    """A URL the app won't use: not https, and not on this machine or the local network."""


def _ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def is_local_host(host: str | None) -> bool:
    """localhost, loopback, private, link-local or `.local`. An empty host is not local."""
    host = (host or "").lower().rstrip(".")
    if not host:
        return False
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        return True
    ip = _ip(host)
    return ip is not None and any(ip in net for net in _PRIVATE_NETS)


def is_secure(url: str) -> bool:
    """https anywhere, or http to a local address."""
    parsed = urlparse(url)
    if parsed.scheme == "https":
        return bool(parsed.hostname)
    return parsed.scheme == "http" and is_local_host(parsed.hostname)


def check_url(url: str, what: str = "This address") -> str:
    """Return `url` unchanged if the app may use it, else raise InsecureURL saying why."""
    url = (url or "").strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise InsecureURL(f"{what} must be a full https:// URL (got {url[:80]!r})")
    if not is_secure(url):
        raise InsecureURL(
            f"{what} uses plain http to {parsed.hostname}, which isn't on this machine or the local "
            "network. Use its https:// address instead."
        )
    return url


_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _carried(addr) -> list:
    """The address, and any IPv4 address carried inside it (NAT64, 6to4, Teredo)."""
    out = [addr]
    if isinstance(addr, ipaddress.IPv6Address):
        if addr in _NAT64:
            out.append(ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF))
        if addr.sixtofour:
            out.append(addr.sixtofour)
        if addr.teredo:
            out.extend(addr.teredo)
    return out


def is_global_ip(ip: str, own: tuple = ()) -> bool:
    """Whether the gateway may connect the container to this address: globally routable, not
    loopback, private, link-local, multicast, reserved or shared (CGNAT), whatever it carries
    inside it, and not on `own` (this computer's networks: own_networks())."""
    addr = _ip(ip)
    if addr is None:
        return False
    return all(a.is_global and not a.is_multicast and not any(a in net for net in own if a.version == net.version)
               for a in _carried(addr))


def own_networks() -> tuple:
    """This computer's addresses and the networks they are on (from its interfaces, read now):
    its global IPv6 prefixes above all, which are routable like anyone's."""
    nets = []
    try:
        with open("/proc/net/if_inet6") as f:
            for line in f:
                hexaddr, _, plen, *_ = line.split()
                addr = ipaddress.IPv6Address(int(hexaddr, 16))
                nets.append(ipaddress.IPv6Network((addr, int(plen, 16)), strict=False))
                nets.append(ipaddress.IPv6Network((addr, 128)))
    except (OSError, ValueError):
        pass
    try:
        names = [n for _, n in socket.if_nameindex()]
    except OSError:
        names = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for name in names:
            req = struct.pack("256s", name.encode()[:15])
            try:
                addr = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, req)[20:24])        # SIOCGIFADDR
                mask = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x891B, req)[20:24])        # SIOCGIFNETMASK
            except OSError:
                continue
            nets.append(ipaddress.IPv4Network(f"{addr}/{mask}", strict=False))
            nets.append(ipaddress.IPv4Network(f"{addr}/32"))
    return tuple(nets)
