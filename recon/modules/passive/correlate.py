"""Entity resolution — collapse many identifiers into one logical service.

The graph accumulates *identifiers*: ``api.example.com``, ``api-v2.example.com``, a bare
IP, a vhost on a shared CDN address. Several of those are frequently **one** logical
service, and until they are linked the coverage model double-counts work, the gap queue
re-probes the same thing under three names, and a finding on one is not visibly a finding
on the others. This module is the glue domain from ``docs/domains/non-binary.md`` §3.12.

**Fully offline.** It reads only fingerprints other modules already captured and stored
(``jarm``, favicon/404/response hashes, certificate SPKI via ``presents_certificate``,
JWKS ``kid`` sets). It sends no traffic, so it is passive: no gate, no ledger debit. That
also makes it deterministic and cheap to re-run as new fingerprints arrive.

**Strength matters more than recall.** A wrong ``same_as`` is worse than a missing one: it
merges two services in the operator's mind and can carry a finding across a boundary that
really exists. So evidence is tiered, and only a *strong* signal mints identity:

===================================  =========  ===================================
signal                               edge       why
===================================  =========  ===================================
certificate SPKI reuse               same_as    the same key material is served
favicon + 404-body hash agree        same_as    two independent body fingerprints
response-body hash (non-trivial)     same_as    byte-identical application response
JWKS ``kid`` set overlap             shared_trust_domain  same token issuer, not same app
JARM / server banner only            co_deploy  same stack or fleet, NOT same identity
===================================  =========  ===================================

A shared ``Server`` header or JARM says "same platform", which is why it produces
``co_deploy`` and never ``same_as`` — half the internet shares an nginx banner.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from ... import verbs
from ...factory import make_edge
from ...models import Verdict
from ..base import Module, ModuleContext, register

#: Whitelisted, deliberately NOT active: this module reads the graph, never the network.
VERB = "fingerprint"

SOURCE = "correlate"

#: Node types worth resolving. Only these carry behaviour fingerprints.
SEED_NODE_TYPES = frozenset({"WebApp", "Host", "Service"})

#: Strong identity fingerprints, in descending confidence. Each entry is
#: ``(attr_name, log_odds, label)``.
STRONG_FINGERPRINTS = (
    ("response_hash", 2.0, "byte-identical response body"),
    ("favicon_hash", 1.6, "favicon hash"),
    ("default_404_hash", 1.4, "404-body hash"),
)

#: Weak signals: same stack/fleet, never the same identity.
WEAK_FINGERPRINTS = (
    ("jarm", 0.4, "JARM TLS fingerprint"),
    ("server", 0.2, "Server banner"),
)

#: Hash values that carry no information — an empty body, a stock error page. Clustering on
#: these would link thousands of unrelated hosts into one bogus "service".
TRIVIAL_HASHES = frozenset({
    "",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # sha256("")
    "d41d8cd98f00b204e9800998ecf8427e",                                  # md5("")
})

#: A cluster larger than this is almost certainly a shared-infrastructure artefact (one CDN
#: edge, one parked-domain page), not one logical service. Reported, never linked.
MAX_CLUSTER = 25

#: Favicon and 404 hashes agreeing is two independent body fingerprints, so the pair is
#: treated as strong even though each alone is mid-strength.
CORROBORATING_PAIR = ("favicon_hash", "default_404_hash")


@dataclass(frozen=True)
class Cluster:
    """A set of node ids that share one fingerprint value."""

    signal: str
    value: str
    members: tuple[str, ...]
    log_odds: float
    label: str

    @property
    def size(self) -> int:
        return len(self.members)


def _fingerprint_clusters(nodes, attr: str) -> list[tuple[str, tuple[str, ...]]]:
    """Group node ids by their value for ``attr``, skipping trivial/missing values."""

    buckets: dict[str, list[str]] = defaultdict(list)
    for node in nodes:
        value = node.attrs.get(attr)
        if not isinstance(value, str):
            continue
        value = value.strip().lower()
        if not value or value in TRIVIAL_HASHES:
            continue
        buckets[value].append(node.id)
    return [(v, tuple(sorted(ids))) for v, ids in buckets.items() if len(ids) > 1]


def _spki_clusters(store) -> list[tuple[str, tuple[str, ...]]]:
    """Group WebApps by the certificate they present.

    Certificate reuse is the strongest signal available here: the same private key is
    being served, which is why ``Certificate`` is keyed on its SPKI/DER in the first place.
    """

    by_cert: dict[str, list[str]] = defaultdict(list)
    for edge in store.edges.values():
        if edge.type != "presents_certificate":
            continue
        by_cert[edge.to].append(edge.frm)
    return [(cert, tuple(sorted(set(ids)))) for cert, ids in by_cert.items()
            if len(set(ids)) > 1]


def _jwks_clusters(nodes) -> list[tuple[str, tuple[str, ...]]]:
    """Group by overlapping JWKS ``kid`` sets — a shared token issuer."""

    by_kid: dict[str, list[str]] = defaultdict(list)
    for node in nodes:
        kids = node.attrs.get("kids")
        if not isinstance(kids, (list, tuple)):
            continue
        for kid in kids:
            if isinstance(kid, str) and kid.strip():
                by_kid[kid.strip()].append(node.id)
    return [(k, tuple(sorted(set(ids)))) for k, ids in by_kid.items() if len(set(ids)) > 1]


@register
class CorrelateModule(Module):
    """Link identifiers that are provably one service, by stored fingerprints only."""

    ctx: ModuleContext

    name = "correlate"
    produces = ()  # emits edges, not nodes
    active = False

    def run(self, seeds: list) -> dict:
        verbs.assert_schedulable(VERB)
        assert not verbs.is_active(VERB), "correlate is passive; its verb must not be active"

        summary: dict = {
            "module": self.name,
            "verb": VERB,
            "active": False,
            "considered": 0,
            "same_as": 0,
            "co_deploy": 0,
            "shared_trust_domain": 0,
            "clusters": [],
            "oversized_clusters": [],
            "blocked": "",
        }

        # Retention needs a current snapshot, same as any other module (I1/I12).
        if not self.ctx.snapshot_ok():
            summary["blocked"] = ("no usable scope snapshot; refusing to mint identity "
                                  "edges against an unpinned policy")
            self.log.info("correlate: %s", summary["blocked"])
            return summary

        store = self.ctx.graph.store
        # Only in-scope nodes participate: linking an out-of-scope identifier would extend
        # an in-scope finding onto something we are not authorized to reason about.
        nodes = [
            n for n in store.nodes.values()
            if n.type in SEED_NODE_TYPES
            and n.scope_binding.verdict == Verdict.IN_SCOPE
        ]
        summary["considered"] = len(nodes)
        if len(nodes) < 2:
            return summary

        clusters: list[Cluster] = []
        for value, members in _spki_clusters(store):
            in_scope = tuple(m for m in members if self._is_in_scope(store, m))
            if len(in_scope) > 1:
                clusters.append(Cluster("certificate_spki", value, in_scope, 2.4,
                                        "serves the same certificate"))
        for attr, odds, label in STRONG_FINGERPRINTS:
            for value, members in _fingerprint_clusters(nodes, attr):
                clusters.append(Cluster(attr, value, members, odds, label))

        # Promote the corroborating pair: two independent body fingerprints agreeing is
        # stronger than either alone.
        paired = self._corroborated_pairs(nodes)

        emitted: set[tuple[str, str, str]] = set()
        for cluster in clusters:
            if cluster.size > MAX_CLUSTER:
                summary["oversized_clusters"].append({
                    "signal": cluster.signal, "size": cluster.size,
                    "reason": "looks like shared infrastructure, not one service",
                })
                self.log.info("correlate: skipping %s cluster of %d (shared infra?)",
                              cluster.signal, cluster.size)
                continue
            bonus = 0.6 if (cluster.signal in CORROBORATING_PAIR
                            and cluster.members in paired) else 0.0
            n = self._link(cluster, "same_as", cluster.log_odds + bonus, emitted)
            summary["same_as"] += n
            if n:
                summary["clusters"].append({
                    "signal": cluster.signal, "members": list(cluster.members),
                    "why": cluster.label,
                })

        for value, members in _jwks_clusters(nodes):
            cluster = Cluster("jwks_kid", value, members, 1.2, "shares a token issuer")
            if cluster.size <= MAX_CLUSTER:
                summary["shared_trust_domain"] += self._link(
                    cluster, "shared_trust_domain", cluster.log_odds, emitted)

        for attr, odds, label in WEAK_FINGERPRINTS:
            for value, members in _fingerprint_clusters(nodes, attr):
                cluster = Cluster(attr, value, members, odds, label)
                if cluster.size <= MAX_CLUSTER:
                    summary["co_deploy"] += self._link(cluster, "co_deploy", odds, emitted)

        self.log.info("correlate: %d nodes -> %d same_as, %d co_deploy, %d shared_trust",
                      summary["considered"], summary["same_as"], summary["co_deploy"],
                      summary["shared_trust_domain"])
        return summary

    # --- helpers -------------------------------------------------------
    @staticmethod
    def _is_in_scope(store, node_id: str) -> bool:
        node = store.get(node_id)
        return node is not None and node.scope_binding.verdict == Verdict.IN_SCOPE

    @staticmethod
    def _corroborated_pairs(nodes) -> set[tuple[str, ...]]:
        """Member sets that cluster identically on BOTH favicon and 404 hashes."""

        sets: dict[str, set[tuple[str, ...]]] = {}
        for attr in CORROBORATING_PAIR:
            sets[attr] = {members for _v, members in _fingerprint_clusters(nodes, attr)}
        return sets[CORROBORATING_PAIR[0]] & sets[CORROBORATING_PAIR[1]]

    def _link(self, cluster: Cluster, edge_type: str, log_odds: float,
              emitted: set) -> int:
        """Link every pair in the cluster with ``edge_type``. Returns edges created.

        Edges are emitted in both directions for ``same_as`` because identity is
        symmetric and the store has no notion of an undirected edge; ``co_deploy`` and
        ``shared_trust_domain`` are likewise symmetric facts.
        """

        count = 0
        members = cluster.members
        for i, left in enumerate(members):
            for right in members[i + 1:]:
                for frm, to in ((left, right), (right, left)):
                    key = (edge_type, frm, to)
                    if key in emitted:
                        continue
                    binding = self.ctx.bind(self._subject(frm))
                    if binding.verdict != Verdict.IN_SCOPE:
                        continue
                    self.ctx.graph.upsert_edge(make_edge(
                        edge_type, frm, to,
                        binding=binding, source=SOURCE, now=self.ctx.clock_now(),
                        attrs={"signal": cluster.signal, "why": cluster.label},
                        log_odds=log_odds,
                    ))
                    emitted.add(key)
                    count += 1
        return count

    @staticmethod
    def _subject(node_id: str) -> str:
        """The host/ip a node id is about, for scope binding."""

        if node_id.startswith("web:"):
            return node_id.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        if node_id.startswith("host:"):
            return node_id[len("host:"):]
        if node_id.startswith("svc:"):
            return node_id[len("svc:"):].rsplit(":", 1)[0]
        return node_id
