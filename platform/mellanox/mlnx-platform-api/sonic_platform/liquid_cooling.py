#
# SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
# Copyright (c) 2019-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
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
#############################################################################
# Mellanox
#
# Module contains an implementation of SONiC Platform Base API and
# provides the liquid cooling status which are available in the platform
#
#############################################################################

try:
    from sonic_platform_base.liquid_cooling_base import LeakageSensorBase,LiquidCoolingBase
    from sonic_py_common.logger import Logger
    from . import utils
    import os
except ImportError as e:
    raise ImportError(str(e) + "- required module not found")

# Global logger class instance
logger = Logger()

LEAKAGE_SENSORS_MAX_NUMBER = 100
LIQUID_COOLING_SENSOR_PATH = "/var/run/hw-management/system/"

class LeakageSensor(LeakageSensorBase):
    def __init__(self, name,path):
        super(LeakageSensor, self).__init__(name)
        self.path = path

    def is_leak(self):
        if os.path.exists(self.path):
            with open(self.path, 'r') as f:
                content = f.read()
                if content == "1":
                    return False
                else:
                    return True
        return False

class LiquidCooling(LiquidCoolingBase):
    """Platform-specific Liquid Cooling class"""

    def __init__(self):
        
        # Count and initialize leakage sensors
        self.leakage_sensors_num = 0
        self.leakage_sensors = []
        for i in range(1, LEAKAGE_SENSORS_MAX_NUMBER):  # Set a reasonable upper limit
            sensor_path = os.path.join(LIQUID_COOLING_SENSOR_PATH, f"leakage{i}")
            if os.path.exists(sensor_path):
                sensor_name = f"leakage{i}"
                self.leakage_sensors[i - 1] = LeakageSensor(sensor_name, sensor_path)
                self.leakage_sensors_num += 1
            else:
                break

        super(LiquidCooling, self).__init__(self.leakage_sensors_num, self.leakage_sensors)

