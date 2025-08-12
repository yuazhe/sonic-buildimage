import os
import sys
from unittest import mock
from sonic_platform.liquid_cooling import LiquidCooling, LeakageSensor

def test_leakage_sensor_init():
    sensor = LeakageSensor("leakage1", "/test/path")
    assert sensor.name == "leakage1"
    assert sensor.path == "/test/path"

def test_leakage_sensor_is_leak():
    sensor = LeakageSensor("leakage1", "/test/path")
    
    # Test when file exists and content is "1" (no leak)
    with mock.patch('os.path.exists') as mock_exists:
        with mock.patch('builtins.open', mock.mock_open(read_data="1")):
            mock_exists.return_value = True
            assert sensor.is_leak() is False

    # Test when file exists and content is "0" (leak detected)
    with mock.patch('os.path.exists') as mock_exists:
        with mock.patch('builtins.open', mock.mock_open(read_data="0")):
            mock_exists.return_value = True
            assert sensor.is_leak() is True

    # Test when file does not exist
    with mock.patch('os.path.exists') as mock_exists:
        mock_exists.return_value = False
        assert sensor.is_leak() is False

def test_liquid_cooling_init():
    # Mock the os.path.exists and os.path.join
    with mock.patch('os.path.exists') as mock_exists:
        with mock.patch('os.path.join') as mock_join:
            # Setup mock to simulate 3 leakage sensors
            mock_exists.side_effect = [True, True, True, False]
            mock_join.side_effect = [
                "/var/run/hw-management/system/leakage1",
                "/var/run/hw-management/system/leakage2", 
                "/var/run/hw-management/system/leakage3",
                "/var/run/hw-management/system/leakage4"
            ]

            liquid_cooling = LiquidCooling()
            
            # Verify the number of sensors initialized
            assert liquid_cooling.get_num_leakage_sensors() == 3
            
            # Verify sensor names
            sensors = liquid_cooling.get_all_leakage_sensors()
            assert len(sensors) == 3
            assert sensors[0].name == "leakage1"
            assert sensors[1].name == "leakage2" 
            assert sensors[2].name == "leakage3"
