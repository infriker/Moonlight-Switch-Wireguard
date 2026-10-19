cmake_minimum_required(VERSION 3.10)
project(WireGuardConfigTests LANGUAGES CXX)

enable_testing()

add_executable(wireguard_config_test
    wireguard_config_test.cpp
    ../app/src/vpn/WireGuardConfig.cpp
)
target_include_directories(wireguard_config_test PRIVATE ../app/src/vpn)
set_target_properties(wireguard_config_test PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)

add_test(NAME wireguard_config_test COMMAND wireguard_config_test)

add_executable(wireguard_routing_test
    wireguard_routing_test.cpp
    ../app/src/vpn/WireGuardRouting.cpp
)
target_include_directories(wireguard_routing_test PRIVATE ../app/src/vpn)
set_target_properties(wireguard_routing_test PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)

add_test(NAME wireguard_routing_test COMMAND wireguard_routing_test)

add_executable(wireguard_manager_disabled_test
    wireguard_manager_disabled_test.cpp
    ../app/src/vpn/WireGuardManager.cpp
    ../app/src/vpn/WireGuardConfig.cpp
    ../app/src/vpn/WireGuardRouting.cpp
)
target_include_directories(wireguard_manager_disabled_test PRIVATE ../app/src/vpn)
set_target_properties(wireguard_manager_disabled_test PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)

add_test(NAME wireguard_manager_disabled_test COMMAND wireguard_manager_disabled_test)
