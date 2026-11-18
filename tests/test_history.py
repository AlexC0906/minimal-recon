import json

import pytest

from minimal_recon.services import history


@pytest.fixture(autouse=True)
def history_home(tmp_path, monkeypatch):
    monkeypatch.setenv("MINIMAL_RECON_HOME", str(tmp_path))
    return tmp_path / "history"


def report(subdomains, days=90, findings=()):
    return {
        "target": "example.test",
        "generated_at": "now",
        "subdomains": {"subdomains": list(subdomains)},
        "tls": {"days_until_expiry": days, "verified": True},
        "anti_spoofing": {"findings": list(findings)},
        "dns": {"records": {"A": ["192.0.2.1"]}},
    }


def test_save_list_load_round_trip(history_home):
    entry = history.save("report", " Example.TEST ", report(["a.example.test"]), {"subdomains": 1})

    assert entry.target == "example.test"
    assert (history_home / f"{entry.id}.json").is_file()
    assert history.list_entries() == [entry]
    assert history.load(entry.id)["data"]["subdomains"]["subdomains"] == ["a.example.test"]


def test_list_filters_and_orders_newest_first():
    first = history.save("report", "example.test", report([]))
    second = history.save("footprint", "alice", {"username": "alice", "results": []})
    third = history.save("report", "other.test", report([]))

    assert [entry.id for entry in history.list_entries()] == [third.id, second.id, first.id]
    assert history.list_entries(kind="footprint") == [second]
    assert [entry.id for entry in history.list_entries(target="EXAMPLE")] == [first.id]


def test_previous_matches_kind_and_target():
    old = history.save("report", "example.test", report([]))
    history.save("report", "other.test", report([]))
    history.save("footprint", "example.test", {"username": "example.test", "results": []})
    new = history.save("report", "example.test", report([]))

    assert history.previous(new) == old
    assert history.previous(old) is None


def test_compare_reports_lists_changes_and_alerts():
    old = history.save("report", "example.test", report(["a.example.test"]))
    new = history.save(
        "report", "example.test", report(["a.example.test", "b.example.test"], days=12, findings=["SPF missing"])
    )

    comparison = history.compare(old.id, new.id)

    paths = {(change["path"], change["change"]) for change in comparison["changes"]}
    assert ("subdomains.subdomains", "added") in paths
    assert ("tls.days_until_expiry", "changed") in paths
    assert "New subdomain: b.example.test" in comparison["alerts"]
    assert "TLS certificate expires in 12 day(s)" in comparison["alerts"]
    assert "New email-spoofing finding: SPF missing" in comparison["alerts"]


def test_compare_footprints_matches_sites_and_ignores_check_times():
    def run(state, checked_at):
        return {"username": "alice", "results": [{"site": "github", "state": state, "checked_at": checked_at}]}

    old = history.save("footprint", "alice", run("not_found", "t1"))
    same = history.save("footprint", "alice", run("not_found", "t2"))
    new = history.save("footprint", "alice", run("found", "t3"))

    assert history.compare(old.id, same.id)["changes"] == []
    assert history.compare(same.id, new.id)["changes"] == [
        {"path": "results.github.state", "change": "changed", "old": "not_found", "new": "found"}
    ]


def test_compare_refuses_different_kinds():
    one = history.save("report", "example.test", report([]))
    two = history.save("footprint", "alice", {"username": "alice", "results": []})

    with pytest.raises(ValueError, match="same kind"):
        history.compare(one.id, two.id)


@pytest.mark.parametrize("entry_id", ["../secret", "..\\x", "20260101T000000000000Z-report-zzzzzz", ""])
def test_invalid_ids_never_touch_the_filesystem(entry_id):
    with pytest.raises(ValueError, match="invalid history entry id"):
        history.load(entry_id)
    with pytest.raises(ValueError):
        history.delete(entry_id)


def test_damaged_files_are_skipped(history_home):
    good = history.save("report", "example.test", report([]))
    (history_home / "20260101T000000000000Z-report-abcdef.json").write_text("{broken", encoding="utf-8")
    (history_home / "notes.json").write_text(json.dumps({"entry": {}}), encoding="utf-8")

    assert history.list_entries() == [good]


def test_delete_and_clear():
    one = history.save("report", "example.test", report([]))
    history.save("report", "example.test", report([]))

    assert history.delete(one.id) is True
    assert history.delete(one.id) is False
    assert history.clear() == 1
    assert history.list_entries() == []


def test_unknown_kind_is_refused():
    with pytest.raises(ValueError):
        history.save("emails", "x", {})


def test_summaries():
    results = [{"site": "github", "found": True}, {"site": "x", "found": False}]

    assert history.summarize_footprint(results) == {"found": 1, "checked": 2, "found_sites": ["github"]}
    summary = history.summarize_report(dict(report(["a", "b"], days=5), whois={"status": "error", "error": "x"}))
    assert summary == {"errors": ["whois"], "subdomains": 2, "tls_days": 5}


def test_alerts_for_invalid_and_expired_certificates():
    expired = {"tls": {"days_until_expiry": -3, "verified": False, "verification_error": "certificate has expired"}}

    assert history.alerts([], expired) == [
        "TLS certificate expired 3 day(s) ago",
        "TLS certificate is not valid: certificate has expired",
    ]
    assert history.alerts([], {"tls": {"status": "error", "error": "timeout"}}) == []


def test_rapid_saves_keep_their_order(monkeypatch):
    from datetime import datetime, timezone

    frozen = datetime(2026, 1, 1, tzinfo=timezone.utc)

    class FrozenClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return frozen

    monkeypatch.setattr(history, "datetime", FrozenClock)
    entries = [history.save("report", "example.test", {"n": index}) for index in range(5)]

    assert [entry.id for entry in history.list_entries()] == [entry.id for entry in reversed(entries)]
    assert history.previous(entries[-1]) == entries[-2]
