"""Whole-job resource ceilings the native protocol does not enforce itself.

Specification section 10 sets them; configuration may lower any value and
never raise it. The supervisor enforces memory, swap, processes and CPU share
through the job's cgroup, scratch bytes through the size of the job's
gVisor tmpfs, CPU seconds by accounting and wall time by its own deadline.
gVisor's tmpfs ignores a node count, so `filesystem_nodes` is not enforced as
a count: every node is sentry memory inside the job's memory limit. See
adr/isolate-validator-trust for that exclusion.
"""

from dataclasses import dataclass, fields


GIB = 1024 ** 3


@dataclass(frozen=True)
class ResourcePolicy:
    cpus: int = 2
    memory_bytes: int = 4 * GIB
    scratch_bytes: int = 8 * GIB
    processes: int = 256
    filesystem_nodes: int = 100_000
    cpu_seconds: int = 300
    wall_seconds: int = 900
    stdout_bytes: int = 65_536
    stderr_bytes: int = 16_384
    open_files: int = 1_024

    def __post_init__(self):
        ceiling = SPECIFICATION
        for item in fields(self):
            value = getattr(self, item.name)
            if type(value) is not int or value < 1:
                raise ValueError("resource-policy-invalid")
            if ceiling is not None and value > getattr(ceiling, item.name):
                raise ValueError("resource-policy-raised")

    def lowered(self, **changes):
        """A policy with some values lowered; raising any value refuses."""
        values = {item.name: getattr(self, item.name) for item in fields(self)}
        for name, value in changes.items():
            if name not in values:
                raise ValueError("resource-policy-invalid")
            values[name] = value
        return ResourcePolicy(**values)

    def record(self):
        return {item.name: getattr(self, item.name) for item in fields(self)}


SPECIFICATION = None
SPECIFICATION = ResourcePolicy()
