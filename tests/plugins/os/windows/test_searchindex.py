from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.helpers.regutil import VirtualHive, VirtualKey
from dissect.target.plugins.os.windows.searchindex import SearchIndexPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_searchindex_db(target_win: Target, fs_win: VirtualFilesystem, hive_hklm: VirtualHive) -> None:
    key_name = "SOFTWARE\\Microsoft\\Windows Search"
    key = VirtualKey(hive_hklm, key_name)
    key.add_value("DataDirectory", "%ProgramData%\\Microsoft\\Search\\Data\\")
    hive_hklm.map_key(key_name, key)

    searchindex_file = absolute_path("_data/plugins/os/windows/searchindex/Windows.db")
    fs_win.map_file("sysvol/Programdata/Microsoft/Search/Data/Applications/Windows/Windows.db", searchindex_file)

    target_win.add_plugin(SearchIndexPlugin)

    records = list(target_win.searchindex())

    # assert len(records) == 3
    assert records[0].filename == "C:/ProgramData/Microsoft/Windows/Start Menu"
    # assert records[0].path == "C:\\Documents\\Example.docx"
    # assert str(records[0].source) == target_file