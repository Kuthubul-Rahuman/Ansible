# Copyright: Contributors to the Ansible project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import annotations

import pytest

from ansible.modules.unarchive import ZipArchive, TgzArchive


@pytest.fixture
def fake_ansible_module():
    return FakeAnsibleModule()


class FakeAnsibleModule:
    def __init__(self):
        self.params = {}
        self.tmpdir = None


class TestCaseZipArchive:
    @pytest.mark.parametrize(
        'side_effect, expected_reason', (
            ([ValueError, '/bin/zipinfo'], "Unable to find required 'unzip'"),
            (ValueError, "Unable to find required 'unzip' or 'zipinfo'"),
        )
    )
    def test_no_zip_zipinfo_binary(self, mocker, fake_ansible_module, side_effect, expected_reason):
        mocker.patch("ansible.modules.unarchive.get_bin_path", side_effect=side_effect)
        fake_ansible_module.params = {
            "extra_opts": "",
            "exclude": "",
            "include": "",
            "io_buffer_size": 65536,
        }

        z = ZipArchive(
            src="",
            b_dest="",
            file_args="",
            module=fake_ansible_module,
        )
        can_handle, reason = z.can_handle_archive()

        assert can_handle is False
        assert expected_reason in reason
        assert z.cmd_path is None

    @pytest.mark.parametrize(
        ("test_input", "expected"),
        [
            pytest.param(
                (1980, 0, 0, 0, 0, 0),
                (1980, 1, 1, 0, 0, 0),
                id="invalid-month-1980",
            ),
            pytest.param(
                (1980, 1, 1, 0, 0, 0),
                (1980, 1, 1, 0, 0, 0),
                id="invalid-year-1979",
            ),
            pytest.param(
                (1981, 1, 1, 0, 0, 0),
                (1981, 1, 1, 0, 0, 0),
                id="valid-datetime",
            ),
            pytest.param(
                (2108, 12, 31, 23, 59, 59),
                (2107, 12, 31, 23, 59, 59),
                id="invalid-year-2108",
            ),
            pytest.param(
                (0,),
                (1980, 1, 1, 0, 0, 0),
                id="invalid-length-datetime",
            ),
        ],
    )
    def test_valid_time_stamp(self, mocker, fake_ansible_module, test_input, expected):
        mocker.patch(
            "ansible.modules.unarchive.get_bin_path",
            side_effect=["/bin/unzip", "/bin/zipinfo"],
        )
        fake_ansible_module.params = {
            "extra_opts": "",
            "exclude": "",
            "include": "",
            "io_buffer_size": 65536,
        }

        z = ZipArchive(
            src="",
            b_dest="",
            file_args="",
            module=fake_ansible_module,
        )
        assert z._valid_time_stamp(test_input) == expected


class TestCaseTgzArchive:
    def test_no_tar_binary(self, mocker, fake_ansible_module):
        mocker.patch("ansible.modules.unarchive.get_bin_path", side_effect=ValueError)
        fake_ansible_module.params = {
            "extra_opts": "",
            "exclude": "",
            "include": "",
            "io_buffer_size": 65536,
        }
        fake_ansible_module.check_mode = False

        t = TgzArchive(
            src="",
            b_dest="",
            file_args="",
            module=fake_ansible_module,
        )
        can_handle, reason = t.can_handle_archive()

        assert can_handle is False
        assert 'Unable to find required' in reason
        assert t.cmd_path is None
        assert t.tar_type is None
