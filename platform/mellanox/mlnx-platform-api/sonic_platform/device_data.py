#
# Copyright (c) 2020-2024 NVIDIA CORPORATION & AFFILIATES.
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

import glob
import os
import time

from . import utils

DEVICE_DATA = {
    'x86_64-mlnx_msn2700-r0': {
        'thermal': {
            "capability": {
                "comex_amb": False
            }
        }
    },
    'x86_64-mlnx_msn2700a1-r0': {
         'thermal': {
            'minimum_table': {
                "unk_trust":   {"-127:30":13, "31:40":14 , "41:120":15},
                "unk_untrust": {"-127:25":13, "26:30":14 , "31:35":15, "36:120":16}
            },
             "capability": {
                 "comex_amb": True
             }
         }
     },
    'x86_64-mlnx_msn2740-r0': {
        'thermal': {
            "capability": {
                "cpu_pack": False,
                "comex_amb": False
            }
        }
    },
    'x86_64-mlnx_msn2100-r0': {
        'thermal': {
            "capability": {
                "cpu_pack": False,
                "comex_amb": False
            }
        }
    },
    'x86_64-mlnx_msn2410-r0': {
        'thermal': {
            "capability": {
                "comex_amb": False
            }
        }
    },
    'x86_64-mlnx_msn2010-r0': {
        'thermal': {
            "capability": {
                "cpu_pack": False,
                "comex_amb": False
            }
        }
    },
    'x86_64-mlnx_msn4700_simx-r0': {
        'thermal': {
            "capability": {
                "cpu_pack": False
            }
        }
    },
    'x86_64-mlnx_msn3700-r0': {
    },
    'x86_64-mlnx_msn3700c-r0': {
    },
    'x86_64-mlnx_msn3800-r0': {
    },
    'x86_64-mlnx_msn4700-r0': {
    },
    'x86_64-mlnx_msn4410-r0': {
    },
    'x86_64-mlnx_msn3420-r0': {
    },
    'x86_64-mlnx_msn4600c-r0': {
    },
    'x86_64-mlnx_msn4600-r0': {
    },
    'x86_64-nvidia_sn4800-r0': {
        'thermal': {
            "capability": {
                "comex_amb": False
            }
        },
        'sfp': {
            'max_port_per_line_card': 16
        }
    },
    'x86_64-nvidia_sn2201-r0': {
        'thermal': {
            "capability": {
                "comex_amb": False,
                "cpu_amb": True
            }
        }
    },
    'x86_64-nvidia_sn5400-r0': {
        'thermal': {
            "capability": {
                "comex_amb": False,
                "pch_temp": True
            }
        }
    },
    'x86_64-nvidia_sn5600-r0': {
        'thermal': {
            "capability": {
                "comex_amb": False,
                "pch_temp": True
            }
        }
    }
}


class DeviceDataManager:
    @classmethod
    @utils.read_only_cache()
    def get_platform_name(cls):
        from sonic_py_common import device_info
        return device_info.get_platform()

    @classmethod
    @utils.read_only_cache()
    def is_simx_platform(cls):
        platform_name = cls.get_platform_name()
        return platform_name and 'simx' in platform_name

    @classmethod
    @utils.read_only_cache()
    def get_fan_drawer_count(cls):
        # Here we don't read from /run/hw-management/config/hotplug_fans because the value in it is not
        # always correct.
        return len(glob.glob('/run/hw-management/thermal/fan*_status')) if cls.is_fan_hotswapable() else 1

    @classmethod
    @utils.read_only_cache()
    def get_fan_count(cls):
        return len(glob.glob('/run/hw-management/thermal/fan*_speed_get'))

    @classmethod
    @utils.read_only_cache()
    def is_fan_hotswapable(cls):
        return utils.read_int_from_file('/run/hw-management/config/hotplug_fans') > 0

    @classmethod
    @utils.read_only_cache()
    def get_psu_count(cls):
        psu_count = utils.read_int_from_file('/run/hw-management/config/hotplug_psus')
        # If psu_count == 0, the platform has fixed PSU
        return psu_count if psu_count > 0 else len(glob.glob('/run/hw-management/config/psu*_i2c_addr'))

    @classmethod
    @utils.read_only_cache()
    def is_psu_hotswapable(cls):
        return utils.read_int_from_file('/run/hw-management/config/hotplug_psus') > 0

    @classmethod
    @utils.read_only_cache()
    def get_sfp_count(cls):
        from sonic_py_common import device_info
        platform_path = device_info.get_path_to_platform_dir()
        platform_json_path = os.path.join(platform_path, 'platform.json')
        platform_data = utils.load_json_file(platform_json_path)
        return len(platform_data['chassis']['sfps'])

    @classmethod
    def get_linecard_sfp_count(cls, lc_index):
        return utils.read_int_from_file('/run/hw-management/lc{}/config/module_counter'.format(lc_index), log_func=None)

    @classmethod
    def get_gearbox_count(cls, sysfs_folder):
        return utils.read_int_from_file(os.path.join(sysfs_folder, 'gearbox_counter'), log_func=None)

    @classmethod
    @utils.read_only_cache()
    def get_cpu_thermal_count(cls):
        return len(glob.glob('run/hw-management/thermal/cpu_core[!_]'))

    @classmethod
    @utils.read_only_cache()
    def get_sodimm_thermal_count(cls):
        return len(glob.glob('/run/hw-management/thermal/sodimm*_temp_input'))

    @classmethod
    @utils.read_only_cache()
    def get_thermal_capability(cls):
        platform_data = DEVICE_DATA.get(cls.get_platform_name(), None)
        if not platform_data:
            return None

        thermal_data = platform_data.get('thermal', None)
        if not thermal_data:
            return None

        return thermal_data.get('capability', None)

    @classmethod
    @utils.read_only_cache()
    def get_linecard_count(cls):
        return utils.read_int_from_file('/run/hw-management/config/hotplug_linecards', log_func=None)

    @classmethod
    @utils.read_only_cache()
    def get_linecard_max_port_count(cls):
        platform_data = DEVICE_DATA.get(cls.get_platform_name(), None)
        if not platform_data:
            return 0

        sfp_data = platform_data.get('sfp', None)
        if not sfp_data:
            return 0
        return sfp_data.get('max_port_per_line_card', 0)

    @classmethod
    def get_bios_component(cls):
        from .component import ComponentBIOS, ComponentBIOSSN2201
        if cls.get_platform_name() in ['x86_64-nvidia_sn2201-r0']:
            # For SN2201, special chass is required for handle BIOS
            # Currently, only fetching BIOS version is supported
            return ComponentBIOSSN2201()
        return ComponentBIOS()

    @classmethod
    def get_cpld_component_list(cls):
        from .component import ComponentCPLD, ComponentCPLDSN2201
        if cls.get_platform_name() in ['x86_64-nvidia_sn2201-r0']:
            # For SN2201, special chass is required for handle BIOS
            # Currently, only fetching BIOS version is supported
            return ComponentCPLDSN2201.get_component_list()
        return ComponentCPLD.get_component_list()

    @classmethod
    @utils.read_only_cache()
    def is_module_host_management_mode(cls):
        from sonic_py_common import device_info
        _, hwsku_dir = device_info.get_paths_to_platform_and_hwsku_dirs()
        sai_profile_file = os.path.join(hwsku_dir, 'sai.profile')
        data = utils.read_key_value_file(sai_profile_file, delimeter='=')
        return data.get('SAI_INDEPENDENT_MODULE_MODE') == '1'
    
    @classmethod
    def wait_platform_ready(cls):
        """
        Wait for Nvidia platform related services(SDK, hw-management) ready
        Returns:
            bool: True if wait success else timeout
        """
        conditions = []
        sysfs_nodes = ['power_mode', 'power_mode_policy', 'present', 'reset', 'status', 'statuserror']
        if cls.is_module_host_management_mode():
            sysfs_nodes.extend(['control', 'frequency', 'frequency_support', 'hw_present', 'hw_reset',
                                'power_good', 'power_limit', 'power_on', 'temperature/input'])
        else:
            conditions.append(lambda: utils.read_int_from_file('/var/run/hw-management/config/asics_init_done') == 1)
        sfp_count = cls.get_sfp_count()
        for sfp_index in range(sfp_count):
            for sysfs_node in sysfs_nodes:
                conditions.append(lambda: os.path.exists(f'/sys/module/sx_core/asic0/module{sfp_index}/{sysfs_node}'))
        return utils.wait_until_conditions(conditions, 300, 1)
