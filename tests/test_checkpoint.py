"""
Tests for vulnhuntr.checkpoint
================================

Covers CheckpointData round-trip, AnalysisCheckpoint lifecycle (start →
set_current → mark_complete → finalize), resume logic, atomic save,
signal handler installation, progress summary, and edge cases.
"""

import json
import signal as sig

from vulnhuntr.checkpoint import AnalysisCheckpoint, CheckpointData
from vulnhuntr.cost_tracker import CostTracker


# ── CheckpointData ─────────────────────────────────────────────────────────


class TestCheckpointData:
    def test_defaults(self):
        cd = CheckpointData()
        assert cd.completed_files == []
        assert cd.pending_files == []
        assert cd.current_file is None
        assert cd.results == []
        assert cd.cost_tracker_data is None

    def test_round_trip(self):
        cd = CheckpointData(
            completed_files=["a.py"],
            pending_files=["b.py", "c.py"],
            current_file="b.py",
            results=[{"file": "a.py", "result": {}}],
            repo_path="/repo",
            model="gpt-4o",
            started_at="2025-01-01T00:00:00",
            last_updated="2025-01-01T00:01:00",
        )
        d = cd.to_dict()
        restored = CheckpointData.from_dict(d)

        assert restored.completed_files == cd.completed_files
        assert restored.pending_files == cd.pending_files
        assert restored.current_file == cd.current_file
        assert restored.repo_path == cd.repo_path
        assert restored.model == cd.model

    def test_from_dict_missing_keys(self):
        """Gracefully handle partial dicts (e.g. old checkpoint format)."""
        cd = CheckpointData.from_dict({"model": "claude"})
        assert cd.model == "claude"
        assert cd.completed_files == []
        assert cd.pending_files == []

    def test_to_dict_keys(self):
        d = CheckpointData().to_dict()
        expected = {
            "completed_files", "pending_files", "current_file", "results",
            "cost_tracker_data", "repo_path", "model", "started_at",
            "last_updated", "vulnhuntr_version",
        }
        assert set(d.keys()) == expected


# ── AnalysisCheckpoint lifecycle ───────────────────────────────────────────


class TestCheckpointLifecycle:
    def _make_checkpoint(self, tmp_path, **kwargs):
        return AnalysisCheckpoint(
            checkpoint_dir=tmp_path / ".chk",
            save_frequency=1,
            **kwargs,
        )

    def test_start_creates_checkpoint_file(self, tmp_path):
        cp = self._make_checkpoint(tmp_path)
        cp.start(
            repo_path=tmp_path,
            files_to_analyze=[tmp_path / "a.py"],
            model="gpt-4o",
        )
        assert cp.checkpoint_file.exists()

    def test_mark_file_complete_moves_to_completed(self, tmp_path):
        cp = self._make_checkpoint(tmp_path)
        a = tmp_path / "a.py"
        b = tmp_path / "b.py"
        cp.start(repo_path=tmp_path, files_to_analyze=[a, b], model="m")

        cp.set_current_file(a)
        cp.mark_file_complete(a, result={"vuln": True})

        data = cp.load()
        assert str(a) in data.completed_files
        assert str(a) not in data.pending_files
        assert len(data.results) == 1

    def test_current_file_cleared_after_complete(self, tmp_path):
        cp = self._make_checkpoint(tmp_path)
        a = tmp_path / "a.py"
        cp.start(repo_path=tmp_path, files_to_analyze=[a], model="m")
        cp.set_current_file(a)
        cp.mark_file_complete(a)
        data = cp.load()
        assert data.current_file is None

    def test_finalize_cleans_up_on_success(self, tmp_path):
        cp = self._make_checkpoint(tmp_path)
        a = tmp_path / "a.py"
        cp.start(repo_path=tmp_path, files_to_analyze=[a], model="m")
        cp.mark_file_complete(a)
        cp.finalize(success=True)
        assert not cp.checkpoint_file.exists()

    def test_finalize_keeps_checkpoint_on_pending(self, tmp_path):
        cp = self._make_checkpoint(tmp_path)
        a = tmp_path / "a.py"
        b = tmp_path / "b.py"
        cp.start(repo_path=tmp_path, files_to_analyze=[a, b], model="m")
        cp.mark_file_complete(a)
        cp.finalize(success=False)
        assert cp.checkpoint_file.exists()


# ── Resume ─────────────────────────────────────────────────────────────────


class TestCheckpointResume:
    def test_can_resume_returns_false_when_no_file(self, tmp_path):
        cp = AnalysisCheckpoint(checkpoint_dir=tmp_path / "nope")
        assert cp.can_resume() is False

    def test_can_resume_returns_true_when_pending(self, tmp_path):
        cp = AnalysisCheckpoint(checkpoint_dir=tmp_path / ".chk", save_frequency=1)
        a = tmp_path / "a.py"
        b = tmp_path / "b.py"
        cp.start(repo_path=tmp_path, files_to_analyze=[a, b], model="m")
        cp.mark_file_complete(a)
        assert cp.can_resume() is True

    def test_resume_restores_cost_tracker(self, tmp_path):
        # Phase 1: build a checkpoint with cost data
        ct1 = CostTracker()
        ct1.track_call(1000, 500, "gpt-4o", file_path="x.py")

        cp1 = AnalysisCheckpoint(checkpoint_dir=tmp_path / ".chk", save_frequency=1)
        cp1.start(
            repo_path=tmp_path,
            files_to_analyze=[tmp_path / "a.py", tmp_path / "b.py"],
            model="gpt-4o",
            cost_tracker=ct1,
        )
        cp1.mark_file_complete(tmp_path / "a.py")
        cp1.save_now()

        # Phase 2: resume into a fresh tracker
        ct2 = CostTracker()
        cp2 = AnalysisCheckpoint(checkpoint_dir=tmp_path / ".chk")
        data = cp2.resume(cost_tracker=ct2)

        assert ct2.total_input_tokens == 1000
        assert ct2.total_output_tokens == 500
        assert len(data.pending_files) == 1

    def test_load_raises_on_missing(self, tmp_path):
        cp = AnalysisCheckpoint(checkpoint_dir=tmp_path / "no_such_dir")
        try:
            cp.load()
            assert False, "Should have raised FileNotFoundError"
        except FileNotFoundError:
            pass


# ── Disabled checkpoint ────────────────────────────────────────────────────


class TestCheckpointDisabled:
    def test_start_is_noop(self, tmp_path):
        cp = AnalysisCheckpoint(
            checkpoint_dir=tmp_path / ".chk", enabled=False,
        )
        cp.start(repo_path=tmp_path, files_to_analyze=[tmp_path / "a.py"], model="m")
        assert not cp.checkpoint_file.exists()

    def test_mark_complete_is_noop(self, tmp_path):
        cp = AnalysisCheckpoint(
            checkpoint_dir=tmp_path / ".chk", enabled=False,
        )
        cp.mark_file_complete(tmp_path / "a.py")
        assert not cp.checkpoint_file.exists()


# ── Progress summary ──────────────────────────────────────────────────────


class TestProgressSummary:
    def test_not_started(self, tmp_path):
        cp = AnalysisCheckpoint(checkpoint_dir=tmp_path / ".chk")
        s = cp.get_progress_summary()
        assert s["status"] == "not_started"

    def test_in_progress(self, tmp_path):
        cp = AnalysisCheckpoint(
            checkpoint_dir=tmp_path / ".chk", save_frequency=99,
        )
        a = tmp_path / "a.py"
        b = tmp_path / "b.py"
        cp.start(repo_path=tmp_path, files_to_analyze=[a, b], model="m")
        cp.mark_file_complete(a)
        s = cp.get_progress_summary()
        assert s["status"] == "in_progress"
        assert s["completed_files"] == 1
        assert s["pending_files"] == 1
        assert s["progress_percent"] == 50.0

    def test_complete(self, tmp_path):
        cp = AnalysisCheckpoint(
            checkpoint_dir=tmp_path / ".chk", save_frequency=99,
        )
        a = tmp_path / "a.py"
        cp.start(repo_path=tmp_path, files_to_analyze=[a], model="m")
        cp.mark_file_complete(a)
        s = cp.get_progress_summary()
        assert s["status"] == "complete"
        assert s["progress_percent"] == 100.0


# ── Atomic save ────────────────────────────────────────────────────────────


class TestAtomicSave:
    def test_checkpoint_is_valid_json(self, tmp_path):
        """Ensure the file on disk is always parseable JSON."""
        cp = AnalysisCheckpoint(checkpoint_dir=tmp_path / ".chk", save_frequency=1)
        a = tmp_path / "a.py"
        cp.start(repo_path=tmp_path, files_to_analyze=[a], model="m")
        cp.mark_file_complete(a)

        with cp.checkpoint_file.open() as f:
            data = json.load(f)
        assert "completed_files" in data

    def test_save_now_forces_write(self, tmp_path):
        cp = AnalysisCheckpoint(
            checkpoint_dir=tmp_path / ".chk",
            save_frequency=999,  # high frequency so auto-save won't trigger
        )
        a = tmp_path / "a.py"
        b = tmp_path / "b.py"
        cp.start(repo_path=tmp_path, files_to_analyze=[a, b], model="m")
        cp.set_current_file(a)
        cp.save_now()

        with cp.checkpoint_file.open() as f:
            data = json.load(f)
        assert data["current_file"] == str(a)


# ── Signal handler ─────────────────────────────────────────────────────────


class TestSignalHandler:
    def test_signal_handler_installed_on_start(self, tmp_path):
        cp = AnalysisCheckpoint(checkpoint_dir=tmp_path / ".chk")
        cp.start(
            repo_path=tmp_path,
            files_to_analyze=[tmp_path / "a.py"],
            model="m",
        )
        # After start, original handler should be saved
        assert cp._original_sigint_handler is not None
        cp._restore_signal_handler()

    def test_signal_handler_restored_on_finalize(self, tmp_path):
        before = sig.getsignal(sig.SIGINT)
        cp = AnalysisCheckpoint(checkpoint_dir=tmp_path / ".chk")
        a = tmp_path / "a.py"
        cp.start(repo_path=tmp_path, files_to_analyze=[a], model="m")
        cp.mark_file_complete(a)
        cp.finalize(success=True)
        after = sig.getsignal(sig.SIGINT)
        # Handler should be restored to whatever it was before
        assert cp._original_sigint_handler is None
        assert before == after
