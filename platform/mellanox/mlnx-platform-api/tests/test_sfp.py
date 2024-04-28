#
# Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES.
# Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import ctypes
import os
import pytest
import shutil
import sys
if sys.version_info.major == 3:
    from unittest import mock
else:
    import mock

test_path = os.path.dirname(os.path.abspath(__file__))
modules_path = os.path.dirname(test_path)
sys.path.insert(0, modules_path)

from sonic_platform.sfp import SFP, RJ45Port, SX_PORT_MODULE_STATUS_INITIALIZING, SX_PORT_MODULE_STATUS_PLUGGED, SX_PORT_MODULE_STATUS_UNPLUGGED, SX_PORT_MODULE_STATUS_PLUGGED_WITH_ERROR, SX_PORT_MODULE_STATUS_PLUGGED_DISABLED
from sonic_platform.chassis import Chassis


class TestSfp:
    @mock.patch('sonic_platform.device_data.DeviceDataManager.get_linecard_count', mock.MagicMock(return_value=8))
    @mock.patch('sonic_platform.device_data.DeviceDataManager.get_linecard_max_port_count')
    def test_sfp_index(self, mock_max_port):
        sfp = SFP(0)
        assert sfp.is_replaceable()
        assert sfp.sdk_index == 0
        assert sfp.index == 1

        mock_max_port.return_value = 16
        sfp = SFP(sfp_index=0, slot_id=1, linecard_port_count=16, lc_name='LINE-CARD1')
        assert sfp.sdk_index == 0
        assert sfp.index == 1

        sfp = SFP(sfp_index=5, slot_id=3, linecard_port_count=16, lc_name='LINE-CARD1')
        assert sfp.sdk_index == 5
        assert sfp.index == 38

        sfp = SFP(sfp_index=1, slot_id=1, linecard_port_count=4, lc_name='LINE-CARD1')
        assert sfp.sdk_index == 1
        assert sfp.index == 5

    @mock.patch('sonic_platform.sfp.SFP.is_sw_control')
    @mock.patch('sonic_platform.sfp.SFP.read_eeprom', mock.MagicMock(return_value=None))
    @mock.patch('sonic_platform.sfp.SFP.shared_sdk_handle', mock.MagicMock(return_value=2))
    @mock.patch('sonic_platform.sfp.SFP._get_module_info')
    @mock.patch('sonic_platform.chassis.Chassis.get_num_sfps', mock.MagicMock(return_value=2))
    @mock.patch('sonic_platform.chassis.extract_RJ45_ports_index', mock.MagicMock(return_value=[]))
    def test_sfp_get_error_status(self, mock_get_error_code, mock_control):
        sfp = SFP(1)
        mock_control.return_value = False
        description_dict = sfp._get_error_description_dict()
        for error in description_dict.keys():
            mock_get_error_code.return_value = (SX_PORT_MODULE_STATUS_PLUGGED_WITH_ERROR, error)
            description = sfp.get_error_description()

            assert description == description_dict[error]

        mock_get_error_code.return_value = (SX_PORT_MODULE_STATUS_PLUGGED_WITH_ERROR, -1)
        description = sfp.get_error_description()
        assert description == "Unknown error (-1)"

        expected_description_list = [
            (SX_PORT_MODULE_STATUS_INITIALIZING, "Initializing"),
            (SX_PORT_MODULE_STATUS_PLUGGED, "OK"),
            (SX_PORT_MODULE_STATUS_UNPLUGGED, "Unplugged"),
            (SX_PORT_MODULE_STATUS_PLUGGED_DISABLED, "Disabled")
        ]
        for oper_code, expected_description in expected_description_list:
            mock_get_error_code.return_value = (oper_code, -1)
            description = sfp.get_error_description()

            assert description == expected_description

        mock_control.return_value = True
        description = sfp.get_error_description()
        assert description == 'Not supported'

        mock_control.side_effect = RuntimeError('')
        description = sfp.get_error_description()
        assert description == 'Initializing'

    @mock.patch('sonic_platform.sfp.SFP._get_page_and_page_offset')
    @mock.patch('sonic_platform.sfp.SFP._is_write_protected')
    def test_sfp_write_eeprom(self, mock_limited_eeprom, mock_get_page):
        sfp = SFP(0)
        assert not sfp.write_eeprom(0, 1, bytearray())

        mock_get_page.return_value = (None, None, None)
        assert not sfp.write_eeprom(0, 1, bytearray([1]))

        mock_get_page.return_value = (0, '/tmp/mock_page', 0)
        mock_limited_eeprom.return_value = True
        assert not sfp.write_eeprom(0, 1, bytearray([1]))

        mock_limited_eeprom.return_value = False
        mo = mock.mock_open()
        print('after mock open')
        with mock.patch('sonic_platform.sfp.open', mo):
            handle = mo()
            handle.write.return_value = 1
            assert sfp.write_eeprom(0, 1, bytearray([1]))

            handle.seek.assert_called_once_with(0)
            handle.write.assert_called_once_with(bytearray([1]))
            handle.write.return_value = -1
            assert not sfp.write_eeprom(0, 1, bytearray([1]))

            handle.write.return_value = 1
            ctypes.set_errno(1)
            assert not sfp.write_eeprom(0, 1, bytearray([1]))
            ctypes.set_errno(0)

            handle.write.side_effect = OSError('')
            assert not sfp.write_eeprom(0, 1, bytearray([1]))

    @mock.patch('sonic_platform.sfp.SFP._get_page_and_page_offset')
    def test_sfp_read_eeprom(self, mock_get_page):
        sfp = SFP(0)
        mock_get_page.return_value = (None, None, None)
        assert sfp.read_eeprom(0, 1) is None

        mock_get_page.return_value = (0, '/tmp/mock_page', 0)
        mo = mock.mock_open()
        with mock.patch('sonic_platform.sfp.open', mo):
            handle = mo()
            handle.read.return_value = b'\x00'
            assert sfp.read_eeprom(0, 1) == bytearray([0])
            handle.seek.assert_called_once_with(0)

            ctypes.set_errno(1)
            assert sfp.read_eeprom(0, 1) is None
            ctypes.set_errno(0)

            handle.read.side_effect = OSError('')
            assert sfp.read_eeprom(0, 1) is None

    @mock.patch('sonic_platform.sfp.SFP._fetch_port_status')
    def test_is_port_admin_status_up(self, mock_port_status):
        mock_port_status.return_value = (0, True)
        assert SFP.is_port_admin_status_up(None, None)

        mock_port_status.return_value = (0, False)
        assert not SFP.is_port_admin_status_up(None, None)

    @mock.patch('sonic_platform.sfp.SFP._get_eeprom_path', mock.MagicMock(return_value = None))
    @mock.patch('sonic_platform.sfp.SFP._get_sfp_type_str')
    @mock.patch('sonic_platform.sfp.SFP.is_sw_control')
    def test_is_write_protected(self, mock_sw_control, mock_get_type_str):
        sfp = SFP(0)
        mock_sw_control.return_value = True
        assert not sfp._is_write_protected(page=0, page_offset=26, num_bytes=1)

        mock_sw_control.return_value = False
        mock_get_type_str.return_value = 'cmis'
        assert sfp._is_write_protected(page=0, page_offset=26, num_bytes=1)
        assert not sfp._is_write_protected(page=0, page_offset=27, num_bytes=1)

        # not exist page
        assert not sfp._is_write_protected(page=3, page_offset=0, num_bytes=1)

        # invalid sfp type str
        mock_get_type_str.return_value = 'invalid'
        assert not sfp._is_write_protected(page=0, page_offset=0, num_bytes=1)

    def test_get_sfp_type_str(self):
        sfp = SFP(0)
        expect_sfp_types = ['cmis', 'sff8636', 'sff8472']
        mock_eeprom_path = '/tmp/mock_eeprom'
        mock_dir = '/tmp/mock_eeprom/0/i2c-0x50'
        os.makedirs(os.path.join(mock_dir), exist_ok=True)
        for expect_sfp_type in expect_sfp_types:
            source_eeprom_file = os.path.join(test_path, 'input_platform', expect_sfp_type + '_page0')
            shutil.copy(source_eeprom_file, os.path.join(mock_dir, 'data'))
            assert sfp._get_sfp_type_str(mock_eeprom_path) == expect_sfp_type
            sfp._sfp_type_str = None

        os.system('rm -rf {}'.format(mock_eeprom_path))
        assert sfp._get_sfp_type_str('invalid') is None

    @mock.patch('os.path.exists')
    @mock.patch('sonic_platform.sfp.SFP._get_eeprom_path')
    @mock.patch('sonic_platform.sfp.SFP._get_sfp_type_str')
    def test_get_page_and_page_offset(self, mock_get_type_str, mock_eeprom_path, mock_path_exists):
        sfp = SFP(0)
        mock_path_exists.return_value = False
        page_num, page, page_offset = sfp._get_page_and_page_offset(0)
        assert page_num is None
        assert page is None
        assert page_offset is None

        mock_path_exists.return_value = True
        mock_eeprom_path.return_value = '/tmp'
        page_num, page, page_offset = sfp._get_page_and_page_offset(255)
        assert page_num == 0
        assert page == '/tmp/0/i2c-0x50/data'
        assert page_offset is 255

        mock_get_type_str.return_value = 'cmis'
        page_num, page, page_offset = sfp._get_page_and_page_offset(256)
        assert page_num == 1
        assert page == '/tmp/1/data'
        assert page_offset is 0

        mock_get_type_str.return_value = 'sff8472'
        page_num, page, page_offset = sfp._get_page_and_page_offset(511)
        assert page_num == -1
        assert page == '/tmp/0/i2c-0x51/data'
        assert page_offset is 255

        page_num, page, page_offset = sfp._get_page_and_page_offset(512)
        assert page_num == 1
        assert page == '/tmp/1/data'
        assert page_offset is 0

    @mock.patch('sonic_platform.sfp.SFP._read_eeprom')
    def test_sfp_get_presence(self, mock_read):
        sfp = SFP(0)
        mock_read.return_value = None
        assert not sfp.get_presence()

        mock_read.return_value = 0
        assert sfp.get_presence()

    @mock.patch('sonic_platform.utils.read_int_from_file')
    def test_rj45_get_presence(self, mock_read_int):
        sfp = RJ45Port(0)
        mock_read_int.return_value = 0
        assert not sfp.get_presence()
        mock_read_int.assert_called_with('/sys/module/sx_core/asic0/module0/present')

        mock_read_int.return_value = 1
        assert sfp.get_presence()

    @mock.patch('sonic_platform.sfp.SFP.get_xcvr_api')
    def test_dummy_apis(self, mock_get_xcvr_api):
        mock_api = mock.MagicMock()
        mock_api.NUM_CHANNELS = 4
        mock_get_xcvr_api.return_value = mock_api

        sfp = SFP(0)
        assert sfp.get_rx_los() == [False] * 4
        assert sfp.get_tx_fault() == [False] * 4

        mock_get_xcvr_api.return_value = None
        assert sfp.get_rx_los() is None
        assert sfp.get_tx_fault() is None

    @mock.patch('sonic_platform.utils.write_file')
    def test_reset(self, mock_write):
        sfp = SFP(0)
        sfp.is_sw_control = mock.MagicMock(return_value=False)
        mock_write.return_value = True
        assert sfp.reset()
        mock_write.assert_called_with('/sys/module/sx_core/asic0/module0/reset', '1')
        sfp.is_sw_control.return_value = True
        assert sfp.reset()
        sfp.is_sw_control.side_effect = Exception('')
        assert not sfp.reset()

    @mock.patch('sonic_platform.sfp.SFP.read_eeprom')
    def test_get_xcvr_api(self, mock_read):
        sfp = SFP(0)
        api = sfp.get_xcvr_api()
        assert api is None
        mock_read.return_value = bytearray([0x18])
        api = sfp.get_xcvr_api()
        assert api is not None

    def test_rj45_basic(self):
        sfp = RJ45Port(0)
        assert not sfp.get_lpmode()
        assert not sfp.reset()
        assert not sfp.set_lpmode(True)
        assert not sfp.get_error_description()
        assert not sfp.get_reset_status()
        assert sfp.read_eeprom(0, 0) is None
        assert sfp.get_transceiver_info()
        assert sfp.get_transceiver_bulk_status()
        assert sfp.get_transceiver_threshold_info()
        sfp.reinit()

    @mock.patch('os.path.exists')
    @mock.patch('sonic_platform.utils.read_int_from_file')
    def test_get_temperature(self, mock_read, mock_exists):
        sfp = SFP(0)
        sfp.is_sw_control = mock.MagicMock(return_value=True)
        mock_exists.return_value = False
        assert sfp.get_temperature() == None

        mock_exists.return_value = True
        assert sfp.get_temperature() == None

        mock_read.return_value = None
        sfp.is_sw_control.return_value = False
        assert sfp.get_temperature() == None

        mock_read.return_value = 448
        assert sfp.get_temperature() == 56.0

    def test_get_temperature_threshold(self):
        sfp = SFP(0)
        sfp.is_sw_control = mock.MagicMock(return_value=True)

        mock_api = mock.MagicMock()
        mock_api.get_transceiver_thresholds_support = mock.MagicMock(return_value=False)
        sfp.get_xcvr_api = mock.MagicMock(return_value=None)
        assert sfp.get_temperature_warning_threshold() is None
        assert sfp.get_temperature_critical_threshold() is None
        
        sfp.get_xcvr_api.return_value = mock_api
        assert sfp.get_temperature_warning_threshold() == 0.0
        assert sfp.get_temperature_critical_threshold() == 0.0

        from sonic_platform_base.sonic_xcvr.fields import consts
        mock_api.get_transceiver_thresholds_support.return_value = True
        mock_api.xcvr_eeprom = mock.MagicMock()
        mock_api.xcvr_eeprom.read = mock.MagicMock(return_value={
            consts.TEMP_HIGH_ALARM_FIELD: 85.0,
            consts.TEMP_HIGH_WARNING_FIELD: 75.0
        })
        assert sfp.get_temperature_warning_threshold() == 75.0
        assert sfp.get_temperature_critical_threshold() == 85.0

    @mock.patch('sonic_platform.utils.read_int_from_file')
    @mock.patch('sonic_platform.device_data.DeviceDataManager.is_module_host_management_mode')
    def test_is_sw_control(self, mock_mode, mock_read):
        sfp = SFP(0)
        mock_mode.return_value = False
        assert not sfp.is_sw_control()
        mock_mode.return_value = True
        
        mock_read.return_value = 0
        assert not sfp.is_sw_control()
        mock_read.return_value = 1
        assert sfp.is_sw_control()

    @mock.patch('sonic_platform.device_data.DeviceDataManager.is_module_host_management_mode', mock.MagicMock(return_value=False))
    @mock.patch('sonic_platform.sfp.SFP.is_sw_control', mock.MagicMock(return_value=False))
    @mock.patch('sonic_platform.utils.is_host', mock.MagicMock(side_effect = [True, True, False, False]))
    @mock.patch('subprocess.check_output', mock.MagicMock(side_effect = ['True', 'False']))
    @mock.patch('sonic_platform.sfp.SFP._get_lpmode', mock.MagicMock(side_effect = [True, False]))
    @mock.patch('sonic_platform.sfp.SFP.sdk_handle', mock.MagicMock(return_value = None))
    def test_get_lpmode(self):
        sfp = SFP(0)
        assert sfp.get_lpmode()
        assert not sfp.get_lpmode()
        assert sfp.get_lpmode()
        assert not sfp.get_lpmode()

    @mock.patch('sonic_platform.device_data.DeviceDataManager.is_module_host_management_mode', mock.MagicMock(return_value=False))
    @mock.patch('sonic_platform.sfp.SFP.is_sw_control', mock.MagicMock(return_value=False))
    @mock.patch('sonic_platform.utils.is_host', mock.MagicMock(side_effect = [True, True, False, False]))
    @mock.patch('subprocess.check_output', mock.MagicMock(side_effect = ['True', 'False']))
    @mock.patch('sonic_platform.sfp.SFP._set_lpmode', mock.MagicMock(side_effect = [True, False]))
    @mock.patch('sonic_platform.sfp.SFP.sdk_handle', mock.MagicMock(return_value = None))
    def test_set_lpmode(self):
        sfp = SFP(0)
        assert sfp.set_lpmode(True)
        assert not sfp.set_lpmode(True)
        assert sfp.set_lpmode(False)
        assert not sfp.set_lpmode(False)
        
    @mock.patch('sonic_platform.device_data.DeviceDataManager.is_module_host_management_mode', mock.MagicMock(return_value=True))
    @mock.patch('sonic_platform.utils.read_int_from_file')
    @mock.patch('sonic_platform.sfp.SFP.is_sw_control')
    def test_get_lpmode_cmis_host_mangagement(self, mock_control, mock_read):
        mock_control.return_value = True
        sfp = SFP(0)
        sfp.get_xcvr_api = mock.MagicMock(return_value=None)
        assert not sfp.get_lpmode()
        
        mock_api = mock.MagicMock()
        sfp.get_xcvr_api.return_value = mock_api
        mock_api.get_lpmode = mock.MagicMock(return_value=False)
        assert not sfp.get_lpmode()
        
        mock_api.get_lpmode.return_value = True
        assert sfp.get_lpmode()
        
        mock_control.return_value = False
        mock_read.return_value = 1
        assert sfp.get_lpmode()
        
        mock_read.return_value = 2
        assert not sfp.get_lpmode()

    @mock.patch('sonic_platform.device_data.DeviceDataManager.is_module_host_management_mode', mock.MagicMock(return_value=True))
    @mock.patch('sonic_platform.sfp.SFP.is_sw_control')
    def test_set_lpmode_cmis_host_mangagement(self, mock_control):
        mock_control.return_value = True
        sfp = SFP(0)
        sfp.get_xcvr_api = mock.MagicMock(return_value=None)
        assert not sfp.set_lpmode(False)
        
        mock_api = mock.MagicMock()
        sfp.get_xcvr_api.return_value = mock_api
        mock_api.get_lpmode = mock.MagicMock(return_value=False)
        assert sfp.set_lpmode(False)
        assert not sfp.set_lpmode(True)
        
        mock_control.return_value = False
        assert not sfp.set_lpmode(True)
        assert not sfp.set_lpmode(False)

    def test_determine_control_type(self):
        sfp = SFP(0)
        sfp.get_xcvr_api = mock.MagicMock(return_value=None)
        assert sfp.determine_control_type() == 0
        
        sfp.get_xcvr_api.return_value = 1 # Just make it not None
        sfp.is_supported_for_software_control = mock.MagicMock(return_value=True)
        assert sfp.determine_control_type() == 1
        
        sfp.is_supported_for_software_control.return_value = False
        assert sfp.determine_control_type() == 0
        
    def test_check_power_capability(self):
        sfp = SFP(0)
        sfp.get_module_max_power = mock.MagicMock(return_value=-1)
        assert not sfp.check_power_capability()
        
        sfp.get_module_max_power.return_value = 48
        sfp.get_power_limit = mock.MagicMock(return_value=48)
        assert sfp.check_power_capability()
        
        sfp.get_power_limit.return_value = 1
        assert not sfp.check_power_capability()
        
    def test_get_module_max_power(self):
        sfp = SFP(0)
        sfp.is_cmis_api = mock.MagicMock(return_value=True)
        sfp.read_eeprom = mock.MagicMock(return_value=bytearray([48]))
        assert sfp.get_module_max_power() == 48
        
        sfp.is_cmis_api.return_value = False
        sfp.is_sff_api = mock.MagicMock(return_value=True)
        sfp.read_eeprom.return_value = bytearray([128])
        assert sfp.get_module_max_power() == 2.5 * 4
        
        sfp.read_eeprom.return_value = bytearray([32])
        assert sfp.get_module_max_power() == 3.2 * 4
        
        # Simulate invalid value
        sfp.read_eeprom.return_value = bytearray([33])
        assert sfp.get_module_max_power() == -1
        
        # Simulate unsupported module type
        sfp.is_sff_api .return_value = False
        assert sfp.get_module_max_power() == -1
        
    def test_update_i2c_frequency(self):
        sfp = SFP(0)
        sfp.get_frequency_support = mock.MagicMock(return_value=False)
        sfp.set_frequency = mock.MagicMock()
        sfp.update_i2c_frequency()
        sfp.set_frequency.assert_not_called()
        
        sfp.get_frequency_support.return_value = True
        sfp.update_i2c_frequency()
        sfp.set_frequency.assert_not_called()
        
        sfp.is_cmis_api = mock.MagicMock(return_value=True)
        sfp.read_eeprom = mock.MagicMock(return_value=bytearray([0]))
        sfp.update_i2c_frequency()
        sfp.set_frequency.assert_called_with(0)
        
        sfp.is_cmis_api.return_value = False
        sfp.is_sff_api = mock.MagicMock(return_value=True)
        sfp.update_i2c_frequency()
        sfp.set_frequency.assert_called_with(0)
        
    def test_disable_tx_for_sff_optics(self):
        sfp = SFP(0)
        mock_api = mock.MagicMock()
        sfp.get_xcvr_api = mock.MagicMock(return_value=mock_api)
        mock_api.tx_disable = mock.MagicMock()
        sfp.disable_tx_for_sff_optics()
        mock_api.tx_disable.assert_not_called()
        
        sfp.is_sff_api = mock.MagicMock(return_value=True)
        mock_api.get_tx_disable_support = mock.MagicMock(return_value=True)
        sfp.disable_tx_for_sff_optics()
        mock_api.tx_disable.assert_called_with(True)
        
    @mock.patch('sonic_platform.utils.read_int_from_file')
    def test_get_error_info_from_sdk_error_type(self, mock_read):
        sfp = SFP(0)
        # Unknown error
        mock_read.return_value = -1
        sfp_state, error_desc = sfp.get_error_info_from_sdk_error_type()
        assert sfp_state == '2'
        assert 'Unknown error' in error_desc
        
        mock_read.return_value = 2
        sfp_state, error_desc = sfp.get_error_info_from_sdk_error_type()
        assert sfp_state == '11'
        assert error_desc is None

    @mock.patch('sonic_platform.chassis.extract_RJ45_ports_index', mock.MagicMock(return_value=[]))
    @mock.patch('sonic_platform.device_data.DeviceDataManager.get_sfp_count', mock.MagicMock(return_value=1))
    def test_initialize_sfp_modules(self):
        c = Chassis()
        c.initialize_sfp()
        s = c._sfp_list[0]
        s.get_hw_present = mock.MagicMock(return_value=True)
        s.get_power_on = mock.MagicMock(return_value=False)
        s.get_reset_state = mock.MagicMock(return_value=True)
        s.get_power_good = mock.MagicMock(return_value=True)
        s.determine_control_type = mock.MagicMock(return_value=1) # software control
        s.set_control_type = mock.MagicMock()
        SFP.initialize_sfp_modules(c._sfp_list)
        assert s.in_stable_state()
        SFP.wait_ready_task.stop()
        SFP.wait_ready_task.join()
        SFP.wait_ready_task = None
