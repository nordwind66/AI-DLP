"""Chunked analysis must find hits that straddle a chunk cut, report absolute offsets and honour its budget.
Needs presidio-analyzer (requirements.txt): python -m pytest services/nlp/tests"""
import os, sys
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
presidio = pytest.importorskip("presidio_analyzer")
from dlp_nlp import presidio_backend as pb


@pytest.fixture(scope="module")
def backend():
    return pb.PresidioBackend()


def test_hits_across_chunk_cuts_have_absolute_offsets(backend):
    filler = "The quarterly report was reviewed by the team on Monday. "
    t = (filler * 400)[:30000]
    marks = []
    for pos in (pb.CHUNK - 10, pb.CHUNK - 3, 2 * pb.CHUNK - 20, 20000):
        ins = " a@b.com "
        t = t[:pos] + ins + t[pos + len(ins):]
        marks.append(pos + 1)
    got = {(d["entity_type"], d["start"]) for d in backend.analyze(t, "auto", [], 0.3)}
    for m in marks:
        assert ("EMAIL_ADDRESS", m) in got, (m, sorted(got))
    # no duplicates from the overlap
    res = backend.analyze(t, "auto", [], 0.3)
    assert len(res) == len({(d["entity_type"], d["start"], d["end"]) for d in res})


def test_budget_is_enforced(backend):
    with pytest.raises(TimeoutError):
        backend.analyze("word " * 40000, "auto", [], 0.3, budget_s=0.0)
