from __future__ import annotations

import re
import urllib.parse
from typing import TYPE_CHECKING, Any, Union, get_args

from dissect.esedb import EseDB
from dissect.sql import sqlite3, SQLite3
from dissect.sql.exceptions import InvalidPageType, NoCellData
from dissect.util.ts import wintimestamp

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.apps.browser.browser import BrowserHistoryRecord
from dissect.target.plugins.apps.browser.edge import EdgePlugin
from dissect.target.plugins.apps.browser.iexplore import InternetExplorerPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.esedb.record import Record as EseDBRecord
    from dissect.esedb.table import Table as EseDBTable

    from dissect.sql.sqlite3 import WALCheckpoint

    from dissect.target.plugins.general.users import UserDetails
    from dissect.target.target import Target

SearchIndexRecord = TargetRecordDescriptor(
    "windows/search/index/entry",
    [
        ("datetime", "ts"),
        ("datetime", "ts_mtime"),
        ("datetime", "ts_btime"),
        ("datetime", "ts_atime"),
        ("path", "path"),
        ("string", "type"),
        ("filesize", "size"),
        ("string", "data"),
        ("path", "source"),
        ("varint", "checkpoint"),
    ],
)

SearchIndexActivityRecord = TargetRecordDescriptor(
    "windows/search/index/activity",
    [
        ("datetime", "ts_start"),
        ("datetime", "ts_end"),
        ("varint", "duration"),
        ("string", "application_name"),
        ("string", "application_id"),
        ("string", "activity_id"),
        ("path", "source"),
        ("varint", "checkpoint"),
    ],
)

SEARCH_INDEX_REGISTRY_KEY = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Search"

RE_URL = re.compile(r"(?P<browser>.+)\:\/\/\{(?P<sid>.+)\}\/(?P<url>.+)$")

BROWSER_RECORD_MAP = {
    "iehistory": InternetExplorerPlugin.BrowserHistoryRecord,
    "winrt": EdgePlugin.BrowserHistoryRecord,
}

SearchIndexRecords = Union[SearchIndexRecord, SearchIndexActivityRecord, BrowserHistoryRecord]


class SearchIndexPlugin(Plugin):
    """Windows Search Index plugin."""

    SYSTEM_PATHS = [
        # Windows 11 22H2 (SQLite3)
        "sysvol/ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.db",
        # Windows Vista and Windows 10 (EseDB)
        "sysvol/ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb",
        # Windows XP (EseDB)
        "sysvol/Documents and Settings/All Users/Application Data/Microsoft/Search/Data/Applications/Windows/Windows.edb",  # noqa: E501
    ]

    USER_PATHS = (
        # Windows 10 Server Roaming (EseDB / SQLite)
        "AppData/Roaming/Microsoft/Search/Data/Applications/S-1-*/*.*db",
    )

    def __init__(self, target: Target):
        super().__init__(target)
        self.databases = set(self.find_databases())

    def find_databases(self) -> Iterator[tuple[Path, UserDetails | None]]:
        seen = set()

        # Find possible custom location of Windows Search Index databases.
        data_dir = self.target.registry.key(SEARCH_INDEX_REGISTRY_KEY).value("DataDirectory").value
        for filename in ["Windows.edb", "Windows.db"]:
            path = self.target.resolve(f"{data_dir}/Applications/Windows/{filename}")
            self.SYSTEM_PATHS.append(path)

        for system_path in self.SYSTEM_PATHS:
            if (path := self.target.fs.path(system_path)).is_file():
                st_info = path.lstat()
                if (digest := (path.name, st_info.st_size, st_info.st_mtime)) not in seen:
                    seen.add(digest)
                    yield path.resolve(), None

        for user_details in self.target.user_details.all_with_home():
            for user_path in self.USER_PATHS:
                for path in user_details.home_path.glob(user_path):
                    st_info = path.lstat()
                    if (digest := (path.name, st_info.st_size, st_info.st_mtime)) not in seen:
                        seen.add(digest)
                        yield path.resolve(), user_details

    def check_compatible(self) -> None:
        if not self.databases:
            raise UnsupportedPluginError("No Windows Search Index database files found on target")

    @export(record=get_args(SearchIndexRecords))
    def search(self) -> Iterator[SearchIndexRecords]:
        """Yield Windows Index Search records.

        Parses ``Windows.edb`` EseDB and ``Windows.db`` SQLite3 databases. Currently does not parse
        ``GatherLogs/SystemIndex/SystemIndex.*.(Crwl|gthr)`` files or ``Windows-gather.db`` and ``Windows-usn.db`` files.

        Windows Search is a standard component of Windows 7 and Windows Vista, and is enabled by default. The standard (non-Windows Server)
        configuration of Windows Search indexes the following paths: ``C:\\Users\\*`` and ``C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\*``,
        with some exceptions for certain file extensions (see the linked references for more information).

        The difference between the fields ``System_Date*`` and ``System_Document_Date*`` should be researched further.
        It is unclear what the field ``InvertedOnlyMD5`` is a checksum of (record or file content?). It might be possible
        to correlate the field ``System_FileOwner`` with a ``UserRecordDescriptor``. The field ``System_FileAttributes`` should be
        investigated further.

        No test data available for indexed Outlook emails, this plugin might not be able to handle indexed email messages.

        References:
            - https://learn.microsoft.com/en-us/windows/win32/search/-search-3x-wds-overview
            - https://github.com/libyal/esedb-kb/blob/main/documentation/Windows%20Search.asciidoc
            - https://www.aon.com/en/insights/cyber-labs/windows-search-index-the-forensic-artifact-youve-been-searching-for
            - https://github.com/strozfriedberg/sidr
            - https://devblogs.microsoft.com/windows-search-platform/configuration-and-settings/
            - https://learn.microsoft.com/en-us/windows/win32/search/-search-3x-wds-included-in-index
        """  # noqa: E501

        for db_path, user_details in self.databases:
            if db_path.suffix == ".edb":
                yield from self.parse_esedb(db_path, user_details)

            elif db_path.suffix == ".db":
                yield from self.parse_sqlite(db_path, user_details)

            else:
                self.target.log.warning("Unknown Windows Search Index database file %r", db_path)

    def parse_esedb(self, path: Path, user_details: UserDetails | None) -> Iterator[SearchIndexRecords]:
        """Parse the EseDB ``SystemIndex_PropertyStore`` table."""

        with path.open("rb") as fh:
            db = EseDB(fh)
            table = db.table("SystemIndex_PropertyStore")

            for record in table.records():
                yield from self.build_record(TableRecord(table, record), user_details, path)

    def parse_sqlite(self, path: Path, user_details: 'UserDetails | None'):
        """Parse the SQLite3 ``SystemIndex_1_PropertyStore`` table, including WAL checkpoints."""

        with path.open("rb") as fh:
            db = SQLite3(fh)

            # Try to open the WAL file if it exists
            wal_path = self.target.fs.path(str(path) + "-wal")
            db_wal = None
            if wal_path.exists():
                db_wal = SQLite3(path.open("rb"))
                db_wal.open_wal(wal_path.open())

            # Read metadata table
            columns = {
                row.get("Id"): row.get("UniqueKey", "").split("-", maxsplit=1)[-1]
                for row in db.table("SystemIndex_1_PropertyStore_Metadata").rows()
            }

            # Read property store table
            if not (table := db.table("SystemIndex_1_PropertyStore")):
                self.target.log.warning("Database %s does not have a table called 'SystemIndex_1_PropertyStore'", path)
                return

            propstore_records = {}
            for row in table.rows():
                work_id = row.get("WorkId")
                column_id = row.get("ColumnId")
                column_name = columns.get(column_id, str(column_id))
                value = row.get("Value")
                if work_id not in propstore_records:
                    propstore_records[work_id] = {column_name: value, "checkpoint": 0}
                else:
                    propstore_records[work_id][column_name] = value

            # Merge WAL changes if present
            if db_wal:
                for checkpoint in db_wal.wal.checkpoints:
                    diff = get_changes_between_db_and_checkpoint(db, checkpoint)
                    for row in diff:  # row = [workid, columnid, value]
                        work_id, column_id, value = row[0], row[1], row[2] if len(row) > 2 else None
                        column_name = columns.get(column_id, str(column_id))
                        if work_id not in propstore_records:
                            propstore_records[work_id] = {column_name: value, "checkpoint": checkpoint.index}
                        else:
                            propstore_records[work_id][column_name] = value
                            propstore_records[work_id]["checkpoint"] = checkpoint.index

            # Yield records
            for values in propstore_records.values():
                yield from self.build_record(values, user_details, path)

    def build_record(
        self, values: dict[str, Any] | TableRecord, user_details: UserDetails | None, db_path: Path
    ) -> Iterator[SearchIndexRecords]:
        """Build a ``SearchIndexRecord``, ``SearchIndexActivityRecord`` or ``HistoryRecord``."""

        if values.get("System_ItemType") == "ActivityHistoryItem":
            yield SearchIndexActivityRecord(
                ts_start=wintimestamp(int.from_bytes(values.get("System_ActivityHistory_StartTime", b""), "little")),
                ts_end=wintimestamp(int.from_bytes(values.get("System_ActivityHistory_EndTime", b""), "little")),
                duration=int.from_bytes(values.get("System_ActivityHistory_ActiveDuration", b""), "little"),
                application_name=values.get("System_Activity_AppDisplayName"),
                application_id=values.get("System_ActivityHistory_AppId"),
                activity_id=values.get("System_ActivityHistory_AppActivityId"),
                source=db_path,
                checkpoint=values.get("checkpoint"),
                _target=self.target,
            )

        elif values.get("System_Search_Store") in ("iehistory", "winrt"):
            system_itemurl = values.get("System_ItemUrl")

            if not system_itemurl or not (match := RE_URL.match(system_itemurl)):
                self.target.log.warning(
                    "Unable to parse System_ItemUrl: %r (%r) in %s", system_itemurl, values, db_path
                )
                return

            browser, sid, url = match.groupdict().values()

            if not (CurrentBrowserHistoryRecord := BROWSER_RECORD_MAP.get(browser)):
                self.target.log.warning(
                    "Unable to determine browser history type for %r (%r) in %s", browser, system_itemurl, db_path
                )
                return

            user = None
            if sid and (sid_user_details := self.target.user_details.find(sid)):
                user = sid_user_details.user

            if not user and user_details:
                user = user_details.user

            yield CurrentBrowserHistoryRecord(
                ts=wintimestamp(int.from_bytes(values.get("System_Link_DateVisited", b""), "little")),
                browser=browser,
                url=values.get("System_Link_TargetUrl") or url,
                title=values.get("System_Title"),
                host=urllib.parse.urlparse(values.get("System_Link_TargetUrl")).hostname or None,
                source=db_path,
                _user=user,
                _target=self.target,
            )

        # System_Search_Store = "file"
        else:
            yield SearchIndexRecord(
                ts=wintimestamp(int.from_bytes(values.get("System_Search_GatherTime", b""), "little")),
                ts_mtime=wintimestamp(int.from_bytes(values.get("System_DateModified", b""), "little")),
                ts_btime=wintimestamp(int.from_bytes(values.get("System_DateCreated", b""), "little")),
                ts_atime=wintimestamp(int.from_bytes(values.get("System_DateAccessed", b""), "little")),
                path=values.get("System_ItemPathDisplay"),
                type=values.get("System_MIMEType")
                or values.get("System_ContentType")
                or values.get("System_ItemTypeText"),
                size=int.from_bytes(b_size, "little") if (b_size := values.get("System_Size")) else None,
                data=values.get("System_Search_AutoSummary"),
                source=db_path,
                checkpoint=values.get("checkpoint"),
                _target=self.target,
            )


class TableRecord:
    def __init__(self, table: EseDBTable, record: EseDBRecord):
        self.table = table
        self.record = record

        # Translates e.g. ``System_DateModified`` to ``15F-System_DateModified`` as these column name prefixes might
        # be dynamic based on the system version.
        self.columns = {col.split("-", maxsplit=1)[-1]: col for col in table.column_names}

    def get(self, key: str, default: Any | None = None) -> Any:
        return self.record.get(self.columns.get(key, default))

def get_changes_between_db_and_checkpoint(db: sqlite3, checkpoint: WALCheckpoint) -> list:
    """Get all changes between the database and a checkpoint.

    Args:
        db (SQLite3): The SQLite3 database to compare the checkpoint to.
        checkpoint (Checkpoint): The checkpoint to compare to the database.
    """
    different_values = []
    for frame in checkpoint.frames:
        try:
            if (db_page := db.page(frame.page_number)) is None:
                db_cell_values = []
            else:
                db_cell_values = [cell.values if cell.size is not None else [] for cell in db_page.cells()]
        except InvalidPageType:
            db_cell_values = []

        try:
            checkpoint_page = frame.page
        except (InvalidPageType, AttributeError):
            checkpoint_page = None

        try:
            checkpoint_cell_values = [cell.values for cell in checkpoint_page.cells()]
        except (NoCellData, AttributeError):
            checkpoint_cell_values = []

        different_values.extend([value for value in checkpoint_cell_values if value not in db_cell_values])

    return different_values
