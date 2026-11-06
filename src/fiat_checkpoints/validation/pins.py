"""Exact executables the validator trusts; never read from a job or a record.

The image build checks every digest below, and the launcher and the native
adapter check them again before each use. A digest here changes only with
`containers/validator.Dockerfile`.
"""

from dataclasses import dataclass
from pathlib import Path


GVISOR_RELEASE = "release-20261019.0"
GVISOR_ARCHIVE_SHA256 = "1298e8ed9c3fee900f00d2ea96ec2d79d80ed93f2175812f29b7e7da718041a3"
GVISOR_ARCHIVE_SHA512 = (
    "7cbc2aeeee809dcccfb40e612504a1b76f2c119790cee59e482f7b35428cccc4"
    "f71705e7e322442d07d1f7d29b5d9e72e31319fc3088d6dcbec9fc7c1f0d8881")
RUNSC_SHA512 = (
    "1ab7bb68955a028d3a82bac6406ee0f9ac0efaf2d6c49adef1d2448251d2b113"
    "1486674c0fe8c2599d680ccd04765f76040d1d8c202f8f9a49ea4c366494f266")
RUNSC_SHA256 = "5b4016fa43a9d35835253925cb6d05d3e42fdb9eb8bcd426c8b25444090e93e6"
GVISOR_SIDECARS = {
    "gvisor-bin/gvisor_sentry": (
        "671db89ebc0ee5b1d27157618649bf30084e5f2b7dfe193c6a0fd326f8e468ba"
        "3d40b68a120924b561ec3c7bf686f331fb57132a620c924cf5d25098103bfca3"),
}
RUNSC_PATH = Path("/opt/fiat-checkpoints/gvisor/runsc")
ROOTFS = Path("/opt/fiat-checkpoints/sandbox/rootfs")
PLATFORM = "systrap"

# Paths inside the sandbox root filesystem.
SANDBOX_PYTHON = "/usr/local/bin/python3.14"
SANDBOX_SERVICE = "/opt/fiat-checkpoints/service"
SANDBOX_TREES = "/opt/fiat-checkpoints/protocol"
# The released native profile omits `scripts/run_observation.py`, which the
# pinned restore, verify and identity commands import. The image adds that one
# file from the same native commit beside a copy of the profile files.
SANDBOX_NATIVE_RUNTIME = "/opt/fiat-checkpoints/native-runtime"
NATIVE_EXTRA = (("scripts/run_observation.py",
                 "712f2afc40f7703cc64a92cd850559684a28f1b98e3241652a67ac6b48124d40"),)
SANDBOX_INPUT = "/input/checkpoint.zip"
SANDBOX_TRUST = "/trust/job.json"
SANDBOX_JOB = "/job"
SANDBOX_UID = 65532


@dataclass(frozen=True)
class Tool:
    name: str
    path: str
    sha256: str
    version: str


# Debian trixie packages at the base image's snapshot, 2026-08-03; Python is
# the base image's own build. ssh-keygen is pinned for the validator role's
# signature checks; the native profile itself uses python, git, gpg, gpgconf.
TOOLS = (
    Tool("python", SANDBOX_PYTHON,
         "30a7def0b3e8d24a36d3829202717542bef124c0a40608b2232b7c837b271bc9", "3.14.6"),
    Tool("git", "/usr/bin/git",
         "356db14e102d68a1a37d8a1ac577dfd678d45d46e92f468bef8b7154e7bfdc60", "1:2.47.3-0+deb13u1"),
    Tool("gpg", "/usr/bin/gpg",
         "7c9d2f9416aabcd10199e2984439f49612644a948279ac56bdf70d69c8958ddf", "2.4.7-21+deb13u1+b4"),
    Tool("gpgconf", "/usr/bin/gpgconf",
         "17ea11378c9d71166df855b73a66333fbf8095cb8da7d3a474bd325e3ca726db", "2.4.7-21+deb13u1+b4"),
    Tool("ssh-keygen", "/usr/bin/ssh-keygen",
         "4a16f170f7c80d6643d3ffada36d396c9d7b1d63238a218628e37af38d6107c0", "1:10.0p1-7+deb13u4"),
)
NATIVE_TOOLS = ("python", "git", "gpg", "gpgconf")


def tool(name):
    return next(item for item in TOOLS if item.name == name)


def record():
    """The pins as one closed record, for evidence and the benchmark report."""
    return {
        "gvisor": {"release": GVISOR_RELEASE, "archive_sha256": GVISOR_ARCHIVE_SHA256,
                   "archive_sha512": GVISOR_ARCHIVE_SHA512, "runsc_sha512": RUNSC_SHA512,
                   "runsc_sha256": RUNSC_SHA256, "platform": PLATFORM},
        "native_extra": [{"path": path, "sha256": sha256} for path, sha256 in NATIVE_EXTRA],
        "tools": [{"name": item.name, "path": item.path, "sha256": item.sha256, "version": item.version}
                  for item in TOOLS],
    }
