import pytest

from recon import verbs
from recon import ontology


def test_allowed_verb_schedulable():
    verbs.assert_schedulable("http-GET")
    verbs.assert_schedulable("resolve")


def test_blocked_verb_never_schedulable():
    with pytest.raises(verbs.BlockedVerb):
        verbs.assert_schedulable("exploit")
    with pytest.raises(verbs.BlockedVerb):
        verbs.assert_schedulable("circumvent")


def test_human_gated_verb_not_autorun():
    with pytest.raises(verbs.HumanGatedVerb):
        verbs.assert_schedulable("content-discovery-wordlist")


def test_unknown_verb_rejected():
    with pytest.raises(verbs.VerbError):
        verbs.assert_schedulable("teleport")


def test_active_classification():
    assert verbs.is_active("http-GET")
    assert not verbs.is_active("passive-collect")


def test_ontology_closed_node_types():
    ontology.assert_node_type("DNSName")
    with pytest.raises(ontology.OntologyError):
        ontology.assert_node_type("Wormhole")


def test_ontology_edge_types_and_proposed():
    ontology.assert_edge_type("resolves_to")
    # proposed edges are declared but not usable
    with pytest.raises(ontology.OntologyError):
        ontology.assert_edge_type("same_as")
    with pytest.raises(ontology.OntologyError):
        ontology.assert_edge_type("not_a_real_edge")
