from dissect.sql import sqlite3
from dissect.sql.sqlite3 import WALCheckpoint
from dissect.sql.exceptions import NoCellData, InvalidPageType
from dissect.esedb.tools import searchindex
from dissect.util.ts import wintimestamp

from dissect.target import Target
from dissect.target.exceptions import (
    PluginError,
    RegistryKeyNotFoundError,
    UnsupportedPluginError,
)
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

from dissect.ntfs.c_ntfs import c_ntfs

SearchIndexFileInfoRecord = TargetRecordDescriptor(
    "filesystem/windows/searchindex/fileinformation",
    [
        ("string", "workid"),  # TODO: remove me
        ("datetime", "record_last_modified"),
        ("string", "filename"),
        ("datetime", "gathertime"),
        ("varint", "SDID"),  # TODO: Check if this could be more human readable. The SDID that is retrieved from the databases does not seem to work in the same as described in the documentation (https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language).
        ("varint", "size"),
        ("string", "date_modified"),
        ("string", "date_created"),
        ("string", "date_accessed"),
        ("string", "owner"),
        ("string", "systemitemtype"),
        ("string", "fileattributes"),
        ("string", "autosummary"), # Apparently obfuscated and compressed in XP, Vista and 7 (https://github.com/libyal/documentation/blob/8f22687893b85299e340f82cae54b482354a4f1d/Forensic%20analysis%20of%20the%20Windows%20Search%20database.pdf)
        ("path", "source"),
        ("string", "latest"),
        ("varint", "checkpointindex"),
    ],
)

SearchIndexFileActivityRecord = TargetRecordDescriptor(
    "filesystem/windows/searchindex/fileactivity",
    [
        ("string", "workid"),  # TODO: remove me
        ("string", "file_contenturi"),
        ("datetime", "starttime"),
        ("datetime", "endtime"),
        ("string", "appid"),
        ("string", "description"),
        ("string", "displaytext"),
        ("string", "itempathdisplay"),
        ("string", "systemitemtype"),
        ("path", "source"),
        ("string", "latest"),
        ("varint", "checkpointindex"),
    ],  # TODO: Who performed. Is not stored in the database? Available columns are: ScopeID, DocumentID, SDID, LastModified, TransactionFlags, TransactionExtendedFlags, CrawlNumberCrawled, StartAddressIdentifier, Priority, FileName, UserData, AppOwnerId, RequiredSIDs, DeletedCount, RunTime, FailureUpdateAttempts, ClientID, LastRequestedRunTime, StorageProviderId, CalculatedPropertyFlags.
)

# TODO: Add support for individual user indexes on Windows Server (https://github.com/fox-it/acquire/pull/200)
FILES = [
    "Applications/Windows/Windows.edb",  # Windows 10 and earlier
    "Applications/Windows/Windows.db",  # Windows 11 (ish? Doesn't seem to be consistent in all Windows 11 implementations)
]

EVENTLOG_REGISTRY_KEY = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Search"

WIN_DATETIME_FIELDS = [
    "LastModified",
    "System_Search_GatherTime",
    "System_DateModified",
    "System_DateCreated",
    "System_DateAccessed",
    "System_ActivityHistory_EndTime",
    "System_ActivityHistory_StartTime",
]

PROPSTORE_INCLUDE_COLUMNS = [
    "WorkID",
    "System_Size",
    "System_DateModified",
    "System_DateCreated",
    "System_DateAccessed",
    "System_FileOwner", # TODO: Only showing for user created data like documents.
    "System_ItemPathDisplay",
    "System_ItemType",
    "System_FileAttributes",
    "System_Search_AutoSummary",
    "System_Activity_ContentUri",
    "System_Activity_Description",
    "System_Activity_DisplayText",
    "System_ActivityHistory_StartTime",
    "System_ActivityHistory_EndTime",
    "System_ActivityHistory_AppId",
    "System_Author",
]


class SearchIndexPlugin(Plugin):
    """Plugin that extracts records from the Windows Search Index database files.

    References:
        - https://www.aon.com/cyber-solutions/aon_cyber_labs/windows-search-index-the-forensic-artifact-youve-been-searching-for/
        - https://github.com/libyal/documentation/blob/8f22687893b85299e340f82cae54b482354a4f1d/Forensic%20analysis%20of%20the%20Windows%20Search%20database.pdf
    """

    def __init__(self, target: Target):
        super().__init__(target)
        self._files = []
        # Check if the registry key exists and get the DataDirectory value
        try:
            datadir = self.target.registry.key(EVENTLOG_REGISTRY_KEY).value("DataDirectory").value
        except RegistryKeyNotFoundError:
            self.target.log.error('No Windows Search registry key "%s" found', EVENTLOG_REGISTRY_KEY)
            return
        except PluginError:
            self.target.log.error("Cannot access registry in target")
            return
        # Check if the database files exist and add them to the _files list
        for filename in FILES:
            databasepath = self.target.resolve(datadir + filename)
            if target.fs.path(databasepath).exists():
                self._files.append(target.fs.path(databasepath))

    def check_compatible(self) -> None:
        if not self._files:
            raise UnsupportedPluginError("No SearchIndex database files found")

    def _get_edb_records(self, path: TargetPath) -> list[dict]:
        """Get records from an EDB file.

        Depends on dissect.esedb/dissect/esedb/tools/searchindex.py.
        Gathers all interesting fields from the SystemIndex_Gthr and SystemIndex_PropertyStore tables and combines them into one dict.

        Args:
            path (Path): Path to the EDB file
        """

        # Open the EDB file with the SearchIndex class from dissect.esedb
        si = searchindex.SearchIndex(path.open("rb"))

        # Get all interesting columns from the Gthr table
        gthr_table_rows = list(
            # Possible include_columns are: ScopeID, DocumentID, SDID, LastModified, TransactionFlags, TransactionExtendedFlags, CrawlNumberCrawled, StartAddressIdentifier, Priority, FileName, UserData, AppOwnerId, RequiredSIDs, DeletedCount, RunTime, FailureUpdateAttempts, ClientID, LastRequestedRunTime, StorageProviderId, CalculatedPropertyFlags
            si.get_table_records("SystemIndex_Gthr", include_columns=["DocumentID", "FileName", "LastModified", "SDID"])
        )
        # Create a dict with DocumentID as key
        gthr_rows = {row["DocumentID"]: row for row in gthr_table_rows}

        # Create a dict with DocumentID as key and a dict with FileName, LastModified and SDID as value
        gthr_records = {}
        for document_id, row in gthr_rows.items():
            if row["LastModified"] is not None:
                last_modified = wintimestamp(int.from_bytes(row["LastModified"], "big"))
            else:
                last_modified = None
            gthr_records[document_id] = {
                "FileName": row["FileName"],
                "LastModified": last_modified,
                "SDID": row["SDID"],
            }

        # print(gthr_records[51])
        # input()

        # Get all interesting columns from the PropertyStore table
        propstore_table_rows = list(
            si.get_table_records(
                "SystemIndex_PropertyStore",
                include_columns=PROPSTORE_INCLUDE_COLUMNS,
            )
        )

        # Create a dict with WorkID as key
        propstore_rows = {row["WorkID"]: row for row in propstore_table_rows}

        # print(propstore_rows[51])
        # input()

        # Create a dict with DocumentID as key and a dict with the column found, convert the LastModified field to a datetime object
        propstore_records = {}
        for work_id, row in propstore_rows.items():
            for column_name in row:
                if row[column_name] is None:
                    continue
                if column_name in WIN_DATETIME_FIELDS:
                    if row[column_name] is not None:
                        try:
                            value = wintimestamp(int.from_bytes(row[column_name], "little"))
                        except ValueError:
                            value = None
                else:
                    value = row[column_name]
                if work_id not in propstore_records.keys():
                    propstore_records[work_id] = [{column_name: value}]
                else:
                    propstore_records[work_id][0][column_name] = value

        # print(propstore_records[51])
        # input()

        rows = []
        # Get the highest ID from both dicts
        max_id = max(max(gthr_records.keys()), max(propstore_records.keys()))
        # Iterate over the highest ID
        for iterator in range(max_id):
            row = {"WorkID": iterator}
            # If the ID is in the gthr_rows dict, add it to the row
            if iterator in gthr_records:
                row = row | gthr_records[iterator]
            # If the ID is in the propstore_rows dict, add it to the row
            if iterator in propstore_records:
                for record in propstore_records[iterator]:
                    rows.append(row | record | {"latest": False})
                rows[-1]["latest"] = True
            # If the row has more than one key, add it to the rows list
            elif len(row) > 1:
                rows.append(row)

        # print(rows[534])
        # input()
        return rows

    def _get_sqlite_records(self, path: TargetPath) -> list[dict]:
        """Get records from a SQLite file.

        Gathers all interesting fields from the SystemIndex_Gthr and
        SystemIndex_PropertyStore tables and combines them into one dict.

        Args:
            path (Path): Path to the SQLite file
        """

        db = sqlite3.SQLite3(path.open("rb"))  # Open the base SQLite file
        if (sqlite_db_wal := self.target.fs.path(str(path) + "-wal")).exists():  # If a WAL file exists, open it
            db_wal = sqlite3.SQLite3(path.open("rb"))  # Open the SQLite file again but with the WAL file
            db_wal.open_wal(sqlite_db_wal.open())
        else:
            db_wal = None

        gather_file = self.target.fs.path(
            "sysvol/programdata/microsoft/search/data/applications/windows/Windows-gather.db"
        )
        gather_db = sqlite3.SQLite3(gather_file.open("rb"))
        if (gather_db_wal := self.target.fs.path(str(gather_file) + "-wal")).exists():
            gather_db.open_wal(gather_db_wal.open())

        gthr_table_rows = sorted(list(gather_db.table("SystemIndex_Gthr")), key=lambda x: x["DocumentID"])

        # Define gthr_records as a dict with DocumentID as key and a dict with FileName, LastModified and SDID as value
        gthr_records = {}
        for row in gthr_table_rows:
            if (last_modified := row["LastModified"]) is not None:
                last_modified = wintimestamp(int.from_bytes(last_modified, "little"))
            gthr_records[row["DocumentID"]] = {
                "FileName": row["FileName"],
                "LastModified": last_modified,
                "SDID": row["SDID"],
            }

        # print(gthr_records[6])
        # input()

        propstore_metadata_table = list(db.table("SystemIndex_1_PropertyStore_Metadata"))

        # Create a workable metadata dict with the column name as value and the column id as key
        propstore_metadata = {}
        for row in propstore_metadata_table:
            column_name = row["PropertyId"].replace(".", "_")
            if column_name in PROPSTORE_INCLUDE_COLUMNS:
                propstore_metadata[row["Id"]] = column_name

        # print(propstore_metadata)
        # input()

        propstore_table_rows = sorted(list(db.table("SystemIndex_1_PropertyStore")), key=lambda x: x["WorkId"])

        # print(propstore_table_rows[51])
        # input()

        propstore_records = {}
        for row in propstore_table_rows:
            work_id = row["WorkId"]
            if row["ColumnId"] not in propstore_metadata:
                continue
            if (column_name := propstore_metadata[row["ColumnId"]]) in WIN_DATETIME_FIELDS:
                if (value := row["Value"]) is not None:
                    try:
                        value = wintimestamp(int.from_bytes(value, "little"))
                    except ValueError:
                        value = None
            else:
                value = row["Value"]
            if work_id not in propstore_records.keys():
                propstore_records[work_id] = [{column_name: value, "checkpointindex": 0}]
            else:
                propstore_records[work_id][0][column_name] = value

        # TODO: figure out which one should be used
        #### STUFF THAT WAS ENABLED ####
        # print(propstore_records[51])
        # print(propstore_records[32])
        # input()

        # if db_wal:
        #     # https://www.sqlite.org/wal.html
        #     for checkpoint in db_wal.wal.checkpoints:
        #         # print("CHECKPOINT", checkpoint.index)
        #         rows = get_rows_from_checkpoint(checkpoint)
        #         for row in rows:  # row = [workid, columnid, value]
        #             # if row[1] == 51:
        #             #     print(row)
        #             work_id = row[0]
        #             if row[1] not in propstore_metadata:
        #                 continue
        #             if (column_name := propstore_metadata[row[1]]) in WIN_DATETIME_FIELDS:
        #                 if (value := row[2]) is not None:
        #                     try:
        #                         value = wintimestamp(int.from_bytes(value, "little"))
        #                     except ValueError:
        #                         value = None
        #             else:
        #                 value = row[2]

        #             if work_id not in propstore_records.keys():
        #                 propstore_records[work_id] = [{column_name: value, "checkpointindex": checkpoint.index}]
        #             elif propstore_records[work_id][-1]["checkpointindex"] < checkpoint.index:
        #                 if propstore_records[work_id][-1].get(column_name) == value:
        #                     print("Not new. skipping")
        #                     continue
        #                 new_dict = propstore_records[work_id][-1].copy()
        #                 new_dict["checkpointindex"] = checkpoint.index
        #                 propstore_records[work_id].append(new_dict)
        #                 if propstore_records[work_id]:
        #                     propstore_records[work_id][-1][column_name] = value
        #             else:
        #                 propstore_records[work_id][-1][column_name] = value
                    
        # print("CHECK DONE")
        # input()
        ####

        #### UNKNOWN ####
        if db_wal:
            for checkpoint in db_wal.wal.checkpoints:
                diff = get_changes_between_db_and_checkpoint(db, checkpoint)
                # print(checkpoint.index, get_workid_from_checkpoint(checkpoint))
                # print(diff)
                # input()

                for row in diff:  # row = [workid, columnid, value]
                    # If the column id is not in the metadata dict, skip the row
                    if row[1] not in propstore_metadata:
                        continue
                    # If the column is a datetime field, convert the value to a datetime object
                    if (column_name := propstore_metadata[row[1]]) in WIN_DATETIME_FIELDS:
                        if (value := row[2]) is not None:
                            try:
                                value = wintimestamp(int.from_bytes(value, "little"))
                            except ValueError:
                                value = None
                    else:
                        # If the column is not a datetime field, just use the value
                        value = row[2]
                    # print(row, column_name, value)
                    if row[0] not in propstore_records.keys():
                        # If the workid is not in the propstore_records dict, add it.
                        # This happens if the WAL contains new workids(/files) which aren't present in the base SQLite file.
                        propstore_records[row[0]] = [
                            {
                                column_name: value,
                                "checkpointindex": checkpoint.index,
                            }
                        ]
                    else:
                        if propstore_records[row[0]][-1]["checkpointindex"] < checkpoint.index:
                            new_dict = propstore_records[row[0]][-1].copy()
                            new_dict["checkpointindex"] = checkpoint.index
                            propstore_records[row[0]].append(new_dict)
                        propstore_records[row[0]][-1][column_name] = value
                    # input()
        ####

        rows = []
        # Get the highest ID from both dicts
        max_id = max(max(gthr_records.keys()), max(propstore_records.keys()))
        # Iterate over the highest ID
        for iterator in range(max_id):
            row = {"WorkID": iterator}
            # If the ID is in the gthr_rows dict, add it to the row
            if iterator in gthr_records:
                row = row | gthr_records[iterator]
            # If the ID is in the propstore_rows dict, add it to the row
            if iterator in propstore_records:
                for record in propstore_records[iterator]:
                    rows.append(row | record | {"latest": False})
                rows[-1]["latest"] = True
            # If the row has more than one key, add it to the rows list
            elif len(row) > 1:
                rows.append(row)

        # print(rows[52])
        # input()

        return rows

    @export(record=SearchIndexFileInfoRecord)
    def searchindex(self):
        """Yield records from the SearchIndex database files."""
        for path in self._files:
            if path.name.endswith(".edb"):
                records = self._get_edb_records(path)
            elif path.name.endswith(".db"):
                records = self._get_sqlite_records(path)

            for record in records:
                if (systemitemtype := record.get("System_ItemType")) == "ActivityHistoryItem":
                    yield SearchIndexFileActivityRecord(
                        workid=record.get("WorkID"),
                        starttime=record.get("System_ActivityHistory_StartTime"),
                        endtime=record.get("System_ActivityHistory_EndTime"),
                        appid=record.get("System_ActivityHistory_AppId"),
                        file_contenturi=record.get("System_Activity_ContentUri"),
                        description=record.get("System_Activity_Description"),
                        displaytext=record.get("System_Activity_DisplayText"),
                        itempathdisplay=record.get("System_ItemPathDisplay"),
                        systemitemtype=systemitemtype,
                        latest=record.get("latest"),
                        source=path,
                        checkpointindex=record.get("checkpointindex"),
                        _target=self.target,
                    )
                else:
                    if (filename := record.get("System_ItemPathDisplay")) is not None:
                        filename = filename.replace("\\", "/")
                    if (autosummary := record.get("System_Search_AutoSummary")) is not None:
                        autosummary = autosummary.encode("utf-8").hex()
                    if (fileattributes := record.get("System_FileAttributes")) is not None:
                        fileattributes = str(c_ntfs.FILE_ATTRIBUTE(fileattributes)).replace("FILE_ATTRIBUTE.", "")
                    yield SearchIndexFileInfoRecord(
                        workid=record.get("WorkID"),
                        record_last_modified=record.get("LastModified"),
                        filename=filename,
                        gathertime=record.get("System_Search_GatherTime"),
                        SDID=record.get("SDID"),
                        size=int.from_bytes(record.get("System_Size"), "little")
                        if record.get("System_Size") is not None
                        else None,
                        date_modified=record.get("System_DateModified"),
                        date_created=record.get("System_DateCreated"),
                        date_accessed=record.get("System_DateAccessed"),
                        owner=record.get("System_FileOwner"),
                        systemitemtype=systemitemtype,
                        fileattributes=fileattributes,
                        autosummary=autosummary,
                        latest=record.get("latest"),
                        source=path,
                        checkpointindex=record.get("checkpointindex"),
                        _target=self.target,
                    )


def get_workid_from_checkpoint(checkpoint: WALCheckpoint) -> list[str]:
    """Get all workids from a checkpoint.

    Args:
        checkpoint (Checkpoint): The checkpoint to get the workids from.
    """
    workids = set()
    for frame in checkpoint.frames:
        try:
            for cell in frame.page.cells():
                try:
                    workids.add(cell.values[0])
                except NoCellData:
                    pass
        except InvalidPageType:
            pass
    return list(workids)


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
                # print("CHECKPOINT", checkpoint.index, "- DB_PAGE", frame.page_number, db_page.header.flags)
                db_cell_values = [cell.values if cell.size is not None else [] for cell in db_page.cells()]
        except InvalidPageType:
            db_cell_values = []

        try:
            checkpoint_page = frame.page
            # print("CHECKPOINT", checkpoint.index, "- CHECK_PAGE", frame.page_number, db_page.header.flags)
        except (InvalidPageType, AttributeError):
            checkpoint_page = None

        try:
            checkpoint_cell_values = [cell.values for cell in checkpoint_page.cells()]
        except (NoCellData, AttributeError):
            checkpoint_cell_values = []

        for value in checkpoint_cell_values:
            if value not in db_cell_values:
                different_values.append(value)

    return different_values


def get_rows_from_checkpoint(checkpoint: WALCheckpoint) -> list[list]:
    """Get all rows from a checkpoint.

    Args:
        checkpoint (Checkpoint): The checkpoint to get the rows from.
    """
    rows = []
    for frame in checkpoint.frames:
        try:
            if frame.page.header.flags != 0xA:
                continue
            for cell in frame.page.cells():
                if cell.size > 255:  # Most likely a large blob and so not related to PropertyStore
                    return []
                rows.append(cell.values)
        except InvalidPageType:
            pass
    return rows
