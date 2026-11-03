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
import http.client
import ipaddress
import re
import socket
import struct
import time
from urllib.parse import urljoin, urlparse

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
    host = (host or "").lower()
    if host.endswith(".") and _ip(host.rstrip(".")) is not None:
        return False                    # 192.168.1.50. is a name to the resolver, not that address: DNS says where
    host = host.rstrip(".")
    if not host:
        return False
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        return True
    ip = _ip(host)
    return ip is not None and any(ip in net for net in _PRIVATE_NETS)


def is_secure(url: str) -> bool:
    """https anywhere, or http to a local address."""
    try:
        parsed = urlparse(url)
        parsed.hostname
    except ValueError:
        return False
    if parsed.scheme == "https":
        return bool(parsed.hostname)
    return parsed.scheme == "http" and is_local_host(parsed.hostname)


def check_url(url: str, what: str = "This address") -> str:
    """Return `url` unchanged if the app may use it, else raise InsecureURL saying why."""
    url = (url or "").strip()
    try:
        parsed = urlparse(url)
        host = parsed.hostname
    except ValueError as e:              # one urlparse can't take (http://[::1]@evil.example/)
        raise InsecureURL(f"{what} isn't an address the app can use ({e}): {url[:80]!r}") from None
    if parsed.scheme not in ("http", "https") or not host:
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


SITE_PREFIX = 48          # what a home network is given of IPv6 at most: its other /64s are its other networks


def own_networks() -> tuple:
    """This computer's addresses and the networks they are on (from its interfaces, read now): its
    global IPv6 prefixes above all, which are routable like anyone's, with the whole /48 around each
    (the rest of what the provider delegated: a guest or IoT network), and every IPv4 address it has
    (a second one on an interface too)."""
    nets = []
    try:
        with open("/proc/net/if_inet6") as f:
            for line in f:
                hexaddr, _, plen, *_ = line.split()
                addr = ipaddress.IPv6Address(int(hexaddr, 16))
                nets.append(ipaddress.IPv6Network((addr, int(plen, 16)), strict=False))
                nets.append(ipaddress.IPv6Network((addr, 128)))
                if addr.is_global:
                    nets.append(ipaddress.IPv6Network((addr, SITE_PREFIX), strict=False))
    except (OSError, ValueError):
        pass
    nets += _fib_ipv4()
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
    return tuple(dict.fromkeys(nets))


def _fib_ipv4(path: str = "/proc/net/fib_trie") -> list:
    """Every IPv4 address of this computer's and the networks on its links, as the kernel's routing
    table has them (SIOCGIFADDR gives only an interface's first address)."""
    out, last = [], None
    try:
        lines = open(path).read().splitlines()
    except OSError:
        return out
    for line in lines:
        if m := re.search(r"[|+]--\s+(\d+\.\d+\.\d+\.\d+)(?:/\d+)?\b", line):
            last = m.group(1)
        elif (m := re.match(r"\s+/(\d+)\s+(\w+)\s+(LOCAL|UNICAST)\b", line)) and last:
            try:
                if m.group(3) == "LOCAL":
                    out.append(ipaddress.IPv4Network(f"{last}/32"))
                elif m.group(2) == "link":
                    out.append(ipaddress.IPv4Network(f"{last}/{m.group(1)}", strict=False))
            except ValueError:
                continue
    return out


# ---- this network's public IPv4 address, as its router has it (never asked of anyone outside it)

def router_public_addresses(timeout: float = 0.6) -> list[str]:
    """The public IPv4 address this network is behind, as its router says it is (NAT-PMP, else UPnP),
    to be refused like the network itself: many routers serve their settings on it to the network
    inside. Only this network's router is asked, at a local address; [] when it doesn't say."""
    found = []
    for ask in (_natpmp_external, _upnp_external):
        try:
            ip = ask(timeout)
        except (OSError, ValueError, http.client.HTTPException):
            ip = None
        if ip and (addr := _ip(ip)) is not None and addr.version == 4 and addr.is_global:
            found.append(str(addr))
            break
    return found


def _default_gateway() -> str | None:
    try:
        lines = open("/proc/net/route").read().splitlines()[1:]
    except OSError:
        return None
    for line in lines:
        f = line.split()
        if len(f) > 3 and f[1] == "00000000" and int(f[3], 16) & 0x2:        # RTF_GATEWAY
            return socket.inet_ntoa(struct.pack("<I", int(f[2], 16)))
    return None


def _natpmp_external(timeout: float) -> str | None:
    gw = _default_gateway()
    if not gw or not is_local_host(gw):
        return None
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(b"\x00\x00", (gw, 5351))         # NAT-PMP: version 0, "what's my external address?"
        data, addr = s.recvfrom(64)
    if addr[0] == gw and len(data) >= 12 and data[0] == 0 and data[1] == 128 and data[2:4] == b"\0\0":
        return socket.inet_ntoa(data[8:12])
    return None


_WAN = re.compile(r"<serviceType>\s*(urn:schemas-upnp-org:service:WAN(?:IP|PPP)Connection:\d)\s*</serviceType>")


def _local_http(url: str, body: bytes | None = None, headers: dict | None = None, timeout: float = 2.0) -> str:
    """One http request to a device on this network (never followed elsewhere), at most 256 KB of it."""
    u = urlparse(url)
    if u.scheme != "http" or not is_local_host(u.hostname):
        raise ValueError(f"{url[:80]} isn't on this network")
    conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    try:
        conn.request("POST" if body is not None else "GET", u.path or "/", body=body, headers=headers or {})
        resp = conn.getresponse()
        if resp.status != 200:
            raise ValueError(f"HTTP {resp.status}")
        return resp.read(256 << 10).decode("utf-8", errors="replace")
    finally:
        conn.close()


def _upnp_external(timeout: float) -> str | None:
    search = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\n"
              "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n").encode()
    locations = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.settimeout(timeout)
        s.sendto(search, ("239.255.255.250", 1900))
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                data, _ = s.recvfrom(4096)
            except OSError:
                break
            if m := re.search(rb"(?im)^location:\s*(\S+)", data):
                locations.append(m.group(1).decode("latin-1"))
    return _upnp_ask(locations)


def _upnp_ask(locations: list[str]) -> str | None:
    """The external address the first of these routers (their description's addresses) gives."""
    for loc in list(dict.fromkeys(locations))[:4]:
        try:
            desc = _local_http(loc)
        except (OSError, ValueError, http.client.HTTPException):
            continue
        for block in re.findall(r"<service>(.*?)</service>", desc, re.S):
            kind, ctrl = _WAN.search(block), re.search(r"<controlURL>\s*([^<\s]+)\s*</controlURL>", block)
            if not (kind and ctrl):
                continue
            soap = (f'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                    f's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
                    f'<u:GetExternalIPAddress xmlns:u="{kind.group(1)}"/></s:Body></s:Envelope>').encode()
            reply = _local_http(urljoin(loc, ctrl.group(1)), soap, {
                "Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{kind.group(1)}#GetExternalIPAddress"'})
            if m := re.search(r"<NewExternalIPAddress>\s*([\d.]+)\s*</NewExternalIPAddress>", reply):
                return m.group(1)
    return None
