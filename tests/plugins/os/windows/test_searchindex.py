from __future__ import annotations

import io
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import Mock, mock_open, patch

import pytest

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.helpers.regutil import VirtualHive, VirtualKey
from dissect.target.plugins.os.windows.searchindex import SearchIndexPlugin

from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.target import Target

@pytest.mark.parametrize(
    ("target", "fs_win", "target_file"),
    [
        (
            "target_win_users",
            "fs_win",
            "\\sysvol\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.db",
        ),
    ],
)
def test_searchindex_db(target: Target, fs_win: VirtualFilesystem, target_file: str, request: pytest.FixtureRequest, hive_hklm: VirtualHive) -> None:
    key_name = "SOFTWARE\\Microsoft\\Windows Search"
    key = VirtualKey(hive_hklm, key_name)
    key.add_value("DataDirectory", "%ProgramData%\\Microsoft\\Search\\Data\\")
    hive_hklm.map_key(key_name, key)


    searchindex_file = absolute_path("_data/plugins/os/windows/searchindex/Windows.db")
    if target_file.startswith("\\sysvol\\"):
        target_file = target_file.replace("\\sysvol\\", "C:\\ProgramData\\")
    fs_win.map_file(target_file, searchindex_file)


    target.add_plugin(SearchIndexPlugin)

    records = list(target.searchindex())

    # assert len(records) == 3
    assert records[0].filename == "C:/ProgramData/Microsoft/Windows/Start Menu"
    # assert records[0].path == "C:\\Documents\\Example.docx"
    # assert str(records[0].source) == target_file