"""Tests for the promotion gate in training/train_verdict_meta.py - added
after a real run on a larger/more diverse dataset (360 rows) produced a
learned meta-model that scored WORSE than the hand-coded baseline it's
supposed to replace (f1 0.909 vs 0.941), reversing the earlier result on
160 rows (0.947 vs 0.919). Promoting unconditionally would have silently
shipped a regression - this gate is what stops that."""
import sys
from pathlib import Path

import pytest

pytest.importorskip("sklearn", reason="requires requirements-mlops.txt")
pytest.importorskip("joblib", reason="requires requirements-mlops.txt")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from training.train_verdict_meta import _should_promote


def test_promotes_when_strictly_better():
    assert _should_promote(new_f1=0.95, baseline_f1=0.90) is True


def test_does_not_promote_when_worse():
    assert _should_promote(new_f1=0.90, baseline_f1=0.95) is False


def test_does_not_promote_on_a_tie():
    assert _should_promote(new_f1=0.90, baseline_f1=0.90) is False
