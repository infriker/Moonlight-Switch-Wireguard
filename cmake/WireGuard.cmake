option(ENABLE_WIREGUARD "Build the in-app WireGuard backend for Nintendo Switch" ON)

function(moonlight_add_wireguard_backend app_target)
    if (NOT PLATFORM_SWITCH OR NOT ENABLE_WIREGUARD)
        return()
    endif ()

    set(_wg_nx_root "${CMAKE_CURRENT_SOURCE_DIR}/extern/wg-nx")
    set(_wg_patch "${CMAKE_CURRENT_SOURCE_DIR}/patches/wg-nx-reliability.patch")
    set(_wg_stage "${CMAKE_BINARY_DIR}/wg-nx-patched")
    set(_wg_lwip "${_wg_nx_root}/library/lwip")

    if (NOT EXISTS "${_wg_nx_root}/src/wireguard.c" OR
            NOT EXISTS "${_wg_nx_root}/include/wireguard.h")
        message(FATAL_ERROR
            "WireGuard is enabled for Switch, but extern/wg-nx is not initialized. "
            "Run: git submodule update --init --checkout extern/wg-nx\n"
            "Then initialize only wg-nx's lwIP dependency with: "
            "git -C extern/wg-nx submodule update --init library/lwip\n"
            "Do not use --recursive: wg-nx also declares SSH-backed and test-only dependencies.")
    endif ()

    if (NOT EXISTS "${_wg_lwip}/src/core/init.c" OR
            NOT EXISTS "${_wg_lwip}/src/include/lwip/init.h")
        message(FATAL_ERROR
            "WireGuard's lwIP submodule is missing or incomplete at ${_wg_lwip}. "
            "Run: git -C extern/wg-nx submodule update --init library/lwip")
    endif ()

    if (NOT EXISTS "${_wg_patch}")
        message(FATAL_ERROR
            "The required wg-nx reliability patch is missing: ${_wg_patch}. "
            "Restore the repository's patches/wg-nx-reliability.patch before configuring WireGuard.")
    endif ()

    find_package(Git REQUIRED)
    find_package(Threads REQUIRED)

    # Reconfigure when the pinned dependency, its lwIP headers, or our patch changes.
    file(GLOB_RECURSE _wg_source_dependencies CONFIGURE_DEPENDS
        "${_wg_nx_root}/src/*"
        "${_wg_nx_root}/include/*"
        "${_wg_nx_root}/library/crypto/*"
        "${_wg_nx_root}/lwip-relay/*"
        "${_wg_lwip}/src/*")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
        "${_wg_patch}" ${_wg_source_dependencies})

    # Stage only the backend directories. This deliberately avoids copying wg-nx's
    # .git directory or initializing its unrelated Borealis/libsodium test deps.
    file(MAKE_DIRECTORY "${_wg_stage}/library")
    file(COPY
        "${_wg_nx_root}/src"
        "${_wg_nx_root}/include"
        "${_wg_nx_root}/lwip-relay"
        DESTINATION "${_wg_stage}")
    file(COPY "${_wg_nx_root}/library/crypto" DESTINATION "${_wg_stage}/library")

    # Git for Windows may have checked out submodule files with CRLF endings,
    # while the source patch is LF. Normalize only the copied files it edits.
    set(_wg_patch_files
        "lwip-relay/include/arch/cc.h"
        "lwip-relay/include/wg_lwip_relay.hpp"
        "lwip-relay/src/wg_lwip_relay.cpp"
        "src/wg_internal.h"
        "src/wg_noise.c"
        "src/wireguard.c")
    foreach(_wg_relative_path IN LISTS _wg_patch_files)
        set(_wg_file "${_wg_stage}/${_wg_relative_path}")
        file(READ "${_wg_file}" _wg_contents)
        string(REPLACE "\r\n" "\n" _wg_contents "${_wg_contents}")
        file(WRITE "${_wg_file}" "${_wg_contents}")
    endforeach ()

    # The build tree may be nested inside this project's checkout. Stop Git's
    # repository discovery at the binary directory so `git apply` treats the
    # staging directory as a plain working directory and cannot silently skip
    # patch paths because of the outer repository prefix.
    execute_process(
        COMMAND "${CMAKE_COMMAND}" -E env
            "GIT_CEILING_DIRECTORIES=${CMAKE_BINARY_DIR}"
            "${GIT_EXECUTABLE}" apply --check "${_wg_patch}"
        WORKING_DIRECTORY "${_wg_stage}"
        RESULT_VARIABLE _wg_patch_check
        OUTPUT_VARIABLE _wg_patch_check_output
        ERROR_VARIABLE _wg_patch_check_error)
    if (NOT _wg_patch_check EQUAL 0)
        message(FATAL_ERROR
            "The wg-nx reliability patch does not apply cleanly to the pinned checkout.\n"
            "git apply --check output:\n${_wg_patch_check_output}${_wg_patch_check_error}")
    endif ()

    execute_process(
        COMMAND "${CMAKE_COMMAND}" -E env
            "GIT_CEILING_DIRECTORIES=${CMAKE_BINARY_DIR}"
            "${GIT_EXECUTABLE}" apply "${_wg_patch}"
        WORKING_DIRECTORY "${_wg_stage}"
        RESULT_VARIABLE _wg_patch_result
        OUTPUT_VARIABLE _wg_patch_output
        ERROR_VARIABLE _wg_patch_error)
    if (NOT _wg_patch_result EQUAL 0)
        message(FATAL_ERROR
            "Failed to apply the wg-nx reliability patch in ${_wg_stage}.\n"
            "git apply output:\n${_wg_patch_output}${_wg_patch_error}")
    endif ()

    file(READ "${_wg_stage}/lwip-relay/include/wg_lwip_relay.hpp" _wg_patched_relay_header)
    file(READ "${_wg_stage}/lwip-relay/include/arch/cc.h" _wg_patched_arch_header)
    string(FIND "${_wg_patched_relay_header}" "pendingLocalDataOffset" _wg_relay_patch_marker)
    string(FIND "${_wg_patched_arch_header}" "#ifndef SSIZE_MAX" _wg_arch_patch_marker)
    if (_wg_relay_patch_marker EQUAL -1 OR _wg_arch_patch_marker EQUAL -1)
        message(FATAL_ERROR
            "Git reported success but the wg-nx reliability patch is not present in ${_wg_stage}. "
            "Expected pendingLocalDataOffset and an SSIZE_MAX guard in the staged sources.")
    endif ()

    file(GLOB _wg_core_sources CONFIGURE_DEPENDS "${_wg_stage}/src/*.c")
    file(GLOB _wg_crypto_sources CONFIGURE_DEPENDS "${_wg_stage}/library/crypto/*.c")

    set(_wg_lwip_sources
        "${_wg_lwip}/src/core/init.c"
        "${_wg_lwip}/src/core/def.c"
        "${_wg_lwip}/src/core/inet_chksum.c"
        "${_wg_lwip}/src/core/ip.c"
        "${_wg_lwip}/src/core/mem.c"
        "${_wg_lwip}/src/core/memp.c"
        "${_wg_lwip}/src/core/netif.c"
        "${_wg_lwip}/src/core/pbuf.c"
        "${_wg_lwip}/src/core/tcp.c"
        "${_wg_lwip}/src/core/tcp_in.c"
        "${_wg_lwip}/src/core/tcp_out.c"
        "${_wg_lwip}/src/core/timeouts.c"
        "${_wg_lwip}/src/core/udp.c"
        "${_wg_lwip}/src/core/ipv4/ip4.c"
        "${_wg_lwip}/src/core/ipv4/ip4_addr.c"
        "${_wg_lwip}/src/core/ipv4/ip4_frag.c"
        "${_wg_lwip}/src/core/ipv4/icmp.c")

    set(_wg_relay_sources
        "${_wg_stage}/lwip-relay/src/wg_lwip_relay.cpp"
        "${_wg_stage}/lwip-relay/src/wg_netif.c"
        "${_wg_stage}/lwip-relay/src/sys_arch.c")

    add_library(moonlight_wireguard_backend STATIC
        ${_wg_core_sources}
        ${_wg_crypto_sources}
        ${_wg_lwip_sources}
        ${_wg_relay_sources})
    set_target_properties(moonlight_wireguard_backend PROPERTIES
        C_STANDARD 99
        C_STANDARD_REQUIRED YES
        # libnx exposes BSD socket constants through its GNU feature profile.
        C_EXTENSIONS YES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS YES)
    target_compile_definitions(moonlight_wireguard_backend PRIVATE __SWITCH__)
    target_include_directories(moonlight_wireguard_backend PRIVATE
        "${_wg_stage}/src"
        "${_wg_stage}/include"
        "${_wg_stage}/library/crypto"
        "${_wg_stage}/lwip-relay/include"
        "${_wg_lwip}/src/include"
        ${APP_PLATFORM_INCLUDE})
    target_compile_options(moonlight_wireguard_backend PRIVATE
        -ffunction-sections
        -fdata-sections
        -march=armv8-a+crc+crypto
        -mtune=cortex-a57
        -mtp=soft
        -fPIC
        $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>
        ${APP_PLATFORM_OPTION})
    target_link_libraries(moonlight_wireguard_backend PRIVATE Threads::Threads)

    target_include_directories(${app_target} PRIVATE
        "${_wg_stage}/src"
        "${_wg_stage}/include"
        "${_wg_stage}/library/crypto"
        "${_wg_stage}/lwip-relay/include"
        "${_wg_lwip}/src/include"
        ${APP_PLATFORM_INCLUDE})
    target_compile_definitions(${app_target} PRIVATE MOONLIGHT_WIREGUARD=1)
    target_link_libraries(${app_target} PRIVATE moonlight_wireguard_backend Threads::Threads)
endfunction()
