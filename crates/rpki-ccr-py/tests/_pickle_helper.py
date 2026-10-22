"""Worker function for the multiprocessing test (must be importable by a spawned child)."""

import rpki_ccr


def instance_size(instance: rpki_ccr.ManifestInstance) -> int:
    return instance.size
