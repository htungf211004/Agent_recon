"""Asset identity and durable v8 to v10 migrations."""

import sqlite3
from datetime import UTC, datetime

from src.contracts.recon_assets import (
    AssetRelation,
    AssetScopeStatus,
    AssetType,
    AssetVerificationStatus,
    DiscoveredAsset,
)
from src.recon.storage import ReconRepository
from src.storage.migrations import MIGRATIONS


def asset(**changes):
    values = dict(run_id="run", task_id="task", root_target="example.test", asset_type=AssetType.PATH,
                  canonical_value="https://example.test/admin?token=secret", relation=AssetRelation.HTML_REFERENCE,
                  discovered_from="root", discovery_evidence_refs=("evidence-1",),
                  scope_status=AssetScopeStatus.IN_SCOPE,
                  verification_status=AssetVerificationStatus.CLASSIFIED)
    return DiscoveredAsset(**(values | changes))


def test_asset_identity_dedupe_and_lifecycle_survive_restart(tmp_path):
    repository = ReconRepository(tmp_path / "recon.db")
    first = repository.upsert_asset(asset())
    assert first.canonical_value == "https://example.test:443/admin"
    assert "secret" not in first.model_dump_json()
    verified = repository.upsert_asset(asset(verification_status=AssetVerificationStatus.VERIFIED,
                                             verification_evidence_refs=("evidence-2",)))
    assert verified.id == first.id
    assert len(repository.asset_inventory("task").assets) == 1
    repository = ReconRepository(tmp_path / "recon.db")
    assert repository.get_asset(first.id).verification_status == AssetVerificationStatus.VERIFIED
    assert repository.list_assets("task", status=AssetVerificationStatus.VERIFIED) == (verified,)
    assert repository.pending_verification_assets("task") == ()
    assert repository.upsert_asset(asset()).verification_status == AssetVerificationStatus.VERIFIED


def test_new_migration_preserves_v8_rows(tmp_path):
    database = tmp_path / "old.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT, applied_at TEXT)")
        for version, name, apply in MIGRATIONS[:8]:
            apply(connection)
            connection.execute("INSERT INTO schema_migrations VALUES (?, ?, ?)",
                               (version, name, datetime.now(UTC).isoformat()))
        connection.execute("INSERT INTO recon_tasks VALUES (?, ?)", ("old-task", '{"legacy": true}'))
        connection.execute("INSERT INTO recon_results VALUES (?, ?)", ("old-task", '{"legacy": true}'))
    repository = ReconRepository(database)
    with repository._connect() as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 10
        assert connection.execute("SELECT payload FROM recon_tasks WHERE id = 'old-task'").fetchone()[0] == '{"legacy": true}'
        assert connection.execute("SELECT payload FROM recon_results WHERE task_id = 'old-task'").fetchone()[0] == '{"legacy": true}'
        assert connection.execute("SELECT name FROM sqlite_master WHERE name = 'origin_recon_work'").fetchone()
