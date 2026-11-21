import pytest
import os
import tempfile
from src.storage import StorageEngine
from src.heuristics import HeuristicsEngine

@pytest.fixture
def temp_storage():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        storage = StorageEngine(tmp.name)
        yield storage

@pytest.fixture
def heuristics():
    return HeuristicsEngine(entropy_threshold=3.85, rate_burst_threshold=5, rate_window_sec=2)
