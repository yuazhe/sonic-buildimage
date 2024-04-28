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
from sonic_platform_base.sonic_thermal_control.thermal_manager_base import ThermalManagerBase
from . import thermal_updater
from .device_data import DeviceDataManager


class ThermalManager(ThermalManagerBase):
    thermal_updater_task = None

    @classmethod
    def run_policy(cls, chassis):
        pass

    @classmethod
    def initialize(cls):
        """
        Initialize thermal manager, including register thermal condition types and thermal action types
        and any other vendor specific initialization.
        :return:
        """
        if DeviceDataManager.is_module_host_management_mode():
            from .chassis import Chassis
            cls.thermal_updater_task = thermal_updater.ThermalUpdater(Chassis.chassis_instance.get_all_sfps())
            cls.thermal_updater_task.start()


    @classmethod
    def deinitialize(cls):
        """
        Destroy thermal manager, including any vendor specific cleanup. The default behavior of this function
        is a no-op.
        :return:
        """
        if DeviceDataManager.is_module_host_management_mode() and cls.thermal_updater_task:
            cls.thermal_updater_task.stop()
