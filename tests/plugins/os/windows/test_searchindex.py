from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.helpers.regutil import VirtualHive, VirtualKey
from dissect.target.plugins.os.windows.searchindex import SearchIndexPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_searchindex_db_dir(target_win: Target, fs_win: VirtualFilesystem, hive_hklm: VirtualHive) -> None:
    key_name = "SOFTWARE\\Microsoft\\Windows Search"
    key = VirtualKey(hive_hklm, key_name)
    # `%ProgramData%\Microsoft\Search\Data` is the default value in the registry, 
    # but it cannot be resolved by `self.target.resolve`. We therefore use the absolute path
    # key.add_value("DataDirectory", "%ProgramData%\\Microsoft\\Search\\Data\\")
    key.add_value("DataDirectory", "C:\\ProgramData\\Microsoft\\Search\\Data\\")
    hive_hklm.map_key(key_name, key)

    searchindex_file = absolute_path("_data/plugins/os/windows/searchindex/db/Windows.db")
    fs_win.map_file("Programdata/Microsoft/Search/Data/Applications/Windows/Windows.db", searchindex_file)

    searchindex_gather_file = absolute_path("_data/plugins/os/windows/searchindex/Windows-gather.db")
    fs_win.map_file("Programdata/Microsoft/Search/Data/Applications/Windows/Windows-gather.db", searchindex_gather_file)

    target_win.apply()

    target_win.add_plugin(SearchIndexPlugin)

    records = list(target_win.searchindex())

    ### Using the `C:\Users\user\example\` directory
    index = 283

    assert records[index].filename == "C:/Users/user/example"
    assert records[index].gathertime == None
    assert records[index].SDID == 1
    assert records[index].size == None
    assert records[index].date_modified == "2025-07-10 17:34:11.790821+00:00"
    assert records[index].date_created == "2025-07-10 17:34:01.286526+00:00"
    assert records[index].date_accessed == "2025-07-10 17:34:15.735374+00:00"
    assert records[index].owner == None
    assert records[index].systemitemtype == "Directory"
    assert records[index].fileattributes == "DIRECTORY"
    assert records[index].autosummary == None
    assert records[index].source == "C:\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.db"
    assert records[index].latest == "True"
    assert records[index].checkpointindex == 0

def test_searchindex_db_file(target_win: Target, fs_win: VirtualFilesystem, hive_hklm: VirtualHive) -> None:
    key_name = "SOFTWARE\\Microsoft\\Windows Search"
    key = VirtualKey(hive_hklm, key_name)
    # `%ProgramData%` is the default value in the registry, but it cannot be resolved by `self.target.resolve`
    # key.add_value("DataDirectory", "%ProgramData%\\Microsoft\\Search\\Data\\")
    key.add_value("DataDirectory", "C:\\ProgramData\\Microsoft\\Search\\Data\\")
    hive_hklm.map_key(key_name, key)

    searchindex_file = absolute_path("_data/plugins/os/windows/searchindex/db/Windows.db")
    fs_win.map_file("Programdata/Microsoft/Search/Data/Applications/Windows/Windows.db", searchindex_file)

    searchindex_gather_file = absolute_path("_data/plugins/os/windows/searchindex/Windows-gather.db")
    fs_win.map_file("Programdata/Microsoft/Search/Data/Applications/Windows/Windows-gather.db", searchindex_gather_file)

    target_win.apply()

    target_win.add_plugin(SearchIndexPlugin)

    records = list(target_win.searchindex())

    ### Using the `C:\Users\user\example\hello-world.txt` file
    index = 329

    assert records[index].filename == "C:/Users/user/example/hello-world.txt"
    assert records[index].gathertime == None
    assert records[index].SDID == 44
    assert records[index].size == 26
    assert records[index].date_modified == "2025-07-10 17:36:03.177847+00:00"
    assert records[index].date_created == "2025-07-10 17:34:08.392567+00:00"
    assert records[index].date_accessed == "2025-07-10 17:36:03.190105+00:00"
    assert records[index].owner == "WIN-PE56TAT6VKU\\user"
    assert records[index].systemitemtype == ".txt"
    assert records[index].fileattributes == "ARCHIVE"
    assert records[index].autosummary == "4c6f72656d20697073756d20646f6c6f722073697420616d6574"
    assert records[index].source == "C:\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.db"
    assert records[index].latest == "True"
    assert records[index].checkpointindex == 0