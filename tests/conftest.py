from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from redready.config import Settings
from redready.db.session import Database


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings.model_validate(
        {
            "database": {"url": f"sqlite:///{tmp_path / 'redready.db'}"},
            "reporting": {"output_dir": str(tmp_path / "reports")},
        }
    )


@pytest.fixture
def db(settings: Settings) -> Iterator[Database]:
    database = Database.from_settings(settings)
    database.create_all()
    yield database
    database.engine.dispose()
