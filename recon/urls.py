"""Canonicalization and id construction — the single source of truth.

``docs/SPEC.md`` §3.1 promises *specified* canonicalization so node ids are deterministic
and merges are idempotent. Before this module existed, host/authority/path rules were
re-implemented in eight separate recon modules, which would inevitably drift and mint two
ids for one thing. Everything that builds a node id goes through here.

The id grammars (mirrored in ``schema/ontology.json``):

===============  ===========================================================
``Domain``       ``domain:<registrable>``
``DNSName``      ``dns:<fqdn>``
``Host``         ``host:<ip>``
``Service``      ``svc:<ip>:<port>/<proto>``
``WebApp``       ``web:<scheme>://<authority>``  (authority keeps a non-default port)
``Route``        ``route:<webapp_id><template>``
``Operation``    ``op:<METHOD>:<route_id>``      (plus ``#<field>`` for GraphQL)
``Parameter``    ``param:<op_id>#<location>:<name>``
``Certificate``  ``cert:<spki_sha256>``
``Hypothesis``   ``hyp:<kind>:<slug>``
===============  ===========================================================
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from urllib.parse import urlsplit, parse_qsl, urlencode

DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}

# A conservative hostname label grammar: alphanumeric + hyphen, not leading/trailing hyphen.
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

# Path segments that are obviously identifiers get collapsed to {id} so one route template
# does not explode into thousands of Route nodes.
_NUMERIC = re.compile(r"^\d+$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_HEX = re.compile(r"^[0-9a-f]{16,}$")

# Multi-part public suffixes. NOTE: this is a pragmatic subset, not the Public Suffix List.
# The rate-ledger key depends on registrable_domain, so getting this wrong means two
# budgets where there should be one. Replace with the real PSL for production.
_MULTI_SUFFIX = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "co.in", "net.in", "org.in", "gen.in", "firm.in",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "net.za",
    "com.mx", "com.ar", "com.tr", "com.sg", "com.hk", "com.tw",
    "co.kr", "or.kr", "github.io",
})


def is_ip(value: str) -> bool:
    value = (value or "").strip().strip("[]").rstrip(".")
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_network(value: str) -> bool:
    if "/" not in (value or ""):
        return False
    try:
        ipaddress.ip_network(value.strip(), strict=False)
        return True
    except ValueError:
        return False


def canonical_host(value: str) -> str:
    """Lower-case, de-scheme, de-port, de-dot and punycode a hostname.

    IPv6 literals keep their brackets stripped here; use :func:`authority` to re-add them.
    """

    host = (value or "").strip().lower()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0]
    if "@" in host:  # strip any userinfo
        host = host.rsplit("@", 1)[1]
    if host.startswith("["):  # bracketed IPv6, optionally with :port
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:  # host:port (a bare IPv6 has >1 colon)
        host = host.split(":", 1)[0]
    host = host.rstrip(".")
    if host and not is_ip(host):
        try:
            host = host.encode("idna").decode("ascii").lower()
        except (UnicodeError, UnicodeDecodeError):
            pass  # leave as-is; valid_fqdn will reject it if malformed
    return host


def valid_fqdn(value: str) -> bool:
    """True for a syntactically plausible hostname (not an IP, not a wildcard)."""

    host = canonical_host(value)
    if not host or len(host) > 253 or is_ip(host):
        return False
    labels = host.split(".")
    if len(labels) < 2:
        return False
    return all(_LABEL.match(l) for l in labels)


def registrable_domain(value: str) -> str:
    """Registrable domain (eTLD+1), used as the unified rate-ledger key."""

    host = canonical_host(value)
    if not host or is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in _MULTI_SUFFIX and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def authority(host: str, port: int | None = None, scheme: str = "") -> str:
    """``host`` or ``host:port``, eliding the scheme's default port, bracketing IPv6."""

    h = canonical_host(host)
    if ":" in h and not is_ip(h):
        pass
    if is_ip(h) and ":" in h:  # IPv6
        h = f"[{h}]"
    if port is None:
        return h
    if scheme and DEFAULT_PORTS.get(scheme) == int(port):
        return h
    return f"{h}:{int(port)}"


def canonical_url(url: str) -> str:
    """Canonical absolute URL: lowercase scheme/host, default port elided, query sorted."""

    parts = urlsplit(url)
    scheme = (parts.scheme or "https").lower()
    auth = authority(parts.hostname or "", parts.port, scheme)
    path = parts.path or "/"
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    return f"{scheme}://{auth}{path}" + (f"?{query}" if query else "")


def path_template(path: str) -> str:
    """Collapse identifier-looking segments so routes don't explode into one-per-id."""

    if not path or not path.startswith("/"):
        path = "/" + (path or "")
    out = []
    for seg in path.split("/"):
        low = seg.lower()
        if _NUMERIC.match(seg) or _UUID.match(low) or _HEX.match(low):
            out.append("{id}")
        else:
            out.append(seg)
    tmpl = "/".join(out)
    # collapse a trailing slash except for the root
    return tmpl if tmpl == "/" else tmpl.rstrip("/") or "/"


# --- id constructors ---------------------------------------------------
def domain_id(value: str) -> str:
    return f"domain:{registrable_domain(value)}"


def dns_id(value: str) -> str:
    return f"dns:{canonical_host(value)}"


def host_id(ip: str) -> str:
    return f"host:{canonical_host(ip)}"


def service_id(ip: str, port: int, proto: str = "tcp") -> str:
    return f"svc:{canonical_host(ip)}:{int(port)}/{proto.lower()}"


def webapp_id(scheme: str, host: str, port: int | None = None) -> str:
    """``web:<scheme>://<authority>`` — keeps a non-default port, unlike the old form."""

    scheme = (scheme or "https").lower()
    return f"web:{scheme}://{authority(host, port, scheme)}"


def webapp_id_from_url(url: str) -> str:
    parts = urlsplit(url)
    return webapp_id(parts.scheme or "https", parts.hostname or "", parts.port)


def route_id(webapp: str, path: str) -> str:
    return f"route:{webapp}{path_template(path)}"


def operation_id(method: str, route: str, field: str = "") -> str:
    base = f"op:{(method or 'GET').upper()}:{route}"
    return f"{base}#{field}" if field else base


def parameter_id(operation: str, name: str, location: str = "query") -> str:
    """``param:<op>#<location>:<name>``.

    The location is part of the identity: a ``query`` and a ``header`` parameter of the
    same name are different inputs, and keying on name alone made them collide on one id —
    which the store would then read as a contradiction and fork on a fact that never
    disagreed.
    """

    return f"param:{operation}#{(location or 'query').lower()}:{name}"


def certificate_id(spki_der: bytes | str) -> str:
    """``cert:<spki_sha256>`` — keying on the SPKI makes key-reuse clustering possible."""

    raw = spki_der.encode() if isinstance(spki_der, str) else spki_der
    return f"cert:{hashlib.sha256(raw).hexdigest()}"


def hypothesis_id(kind: str, slug: str) -> str:
    return f"hyp:{kind}:{slug}"
