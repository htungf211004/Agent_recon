"""Explicitly select promoted runner datasets for a live run."""

from src.contracts.recon_kb import StorageClass
from src.recon.kb.runner import RunnerDataResolver
from src.recon.wordlists import install_external_wordlist
from src.storage.recon_kb import KBSnapshotStore


def select_runner_data(repository, run_id: str, selections, *, root="data/recon_kb"):
    store = KBSnapshotStore(root)
    bindings = {item.source_id: item for item in repository.kb_snapshots(run_id)}
    selected = []
    for selection in dict.fromkeys(selections):
        source_id, separator, runner_data_id = selection.partition(":")
        if not separator or not source_id or not runner_data_id:
            raise ValueError("runner data selection must be SOURCE_ID:runner_data_id")
        bound = bindings.get(source_id)
        if bound is not None:
            if bound.storage_class != StorageClass.RUNNER_DATA:
                raise ValueError("source is already bound as a different storage class")
            snapshot_id = bound.snapshot_id
        else:
            snapshot_id = store.pointer(source_id, "CURRENT")
            if not snapshot_id:
                raise ValueError(f"{source_id} has no promoted CURRENT snapshot")
        resolver = RunnerDataResolver(store, source_id, snapshot_id)
        wordlist = resolver.resolve(runner_data_id, automatic=False)
        repository.pin_kb_snapshot(run_id, resolver.manifest)
        install_external_wordlist(wordlist)
        selected.append(selection)
    return tuple(selected)
