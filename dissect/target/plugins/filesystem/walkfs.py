from typing import Iterator

from dissect.util.ts import from_unix

from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.filesystem import FilesystemEntry, LayerFilesystemEntry
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, arg, export
from dissect.target.target import Target
import math

FilesystemRecord = TargetRecordDescriptor(
    "filesystem/entry",
    [
        ("datetime", "atime"),
        ("datetime", "mtime"),
        ("datetime", "ctime"),
        ("datetime", "btime"),
        ("varint", "ino"),
        ("path", "path"),
        ("filesize", "size"),
        ("uint32", "mode"),
        ("uint32", "uid"),
        ("uint32", "gid"),
        ("string[]", "fstypes"),
        ("float", "entropy"),
    ],
)


class WalkFSPlugin(Plugin):
    """Filesystem agnostic walkfs plugin."""

    def check_compatible(self) -> None:
        if not len(self.target.filesystems):
            raise UnsupportedPluginError("No filesystems to walk")

    @export(record=FilesystemRecord)
    @arg("--walkfs-path", default="/", help="path to recursively walk")
    @arg("--calculate-entropy", action="store_true", help="calculate entropy for each file")
    def walkfs(self, walkfs_path: str = "/", calculate_entropy: bool = False) -> Iterator[FilesystemRecord]:
        """Walk a target's filesystem and return all filesystem entries."""

        path = self.target.fs.path(walkfs_path)

        if not path.exists():
            self.target.log.error("No such directory: '%s'", walkfs_path)
            return

        if not path.is_dir():
            self.target.log.error("Not a directory: '%s'", walkfs_path)
            return

        for entry in self.target.fs.recurse(walkfs_path):
            try:
                entropy = 0

                if not entry.is_dir() and calculate_entropy:
                    entropy = _calculate_entropy(entry)

                yield generate_record(self.target, entry, entropy)

            except FileNotFoundError as e:
                self.target.log.warning("File not found: %s", entry)
                self.target.log.debug("", exc_info=e)
            except Exception as e:
                self.target.log.warning("Exception generating record for: %s, %s", entry, e)
                self.target.log.debug("", exc_info=e)
                continue


def _calculate_entropy(path: str) -> float:
    """Calculate the entropy of a file.
    
    Args:
        path: Path to the file to calculate the entropy of.
    
    Returns:
        The calculated entropy.

    References:
        - https://stackoverflow.com/questions/59528143/compute-entropy-of-a-pickle-file
    """
    with path.open() as file:
        counters = {byte: 0 for byte in range(2 ** 8)}  # start all counters with zeros

        for byte in file.read():  # read in chunks for large files
            counters[byte] += 1  # increase counter for specified byte

        filesize = file.tell()  # we can get file size by reading current position

        if filesize > 0:
            probabilities = [counter / filesize for counter in counters.values()]  # calculate probabilities for each byte
            entropy = -sum(probability * math.log2(probability) for probability in probabilities if probability > 0)  # final sum
        else:
            entropy = 0  # set entropy to 0 if file size is zero
        return entropy


def generate_record(target: Target, entry: FilesystemEntry, entropy: str) -> FilesystemRecord:
    """Generate a :class:`FilesystemRecord` from the given :class:`FilesystemEntry`.

    Args:
        target: :class:`Target` instance
        entry: :class:`FilesystemEntry` instance

    Returns:
        Generated :class:`FilesystemRecord` for the given :class:`FilesystemEntry`.
    """
    stat = entry.lstat()

    if isinstance(entry, LayerFilesystemEntry):
        fs_types = [sub_entry.fs.__type__ for sub_entry in entry.entries]
    else:
        fs_types = [entry.fs.__type__]

    return FilesystemRecord(
        atime=from_unix(stat.st_atime),
        mtime=from_unix(stat.st_mtime),
        ctime=from_unix(stat.st_ctime),
        btime=from_unix(stat.st_birthtime) if stat.st_birthtime else None,
        ino=stat.st_ino,
        path=entry.path,
        size=stat.st_size,
        mode=stat.st_mode,
        uid=stat.st_uid,
        gid=stat.st_gid,
        fstypes=fs_types,
        entropy=entropy,
        _target=target,
    )
