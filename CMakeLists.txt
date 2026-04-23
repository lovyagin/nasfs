cmake_minimum_required(VERSION 3.10)
project(nasfs VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Build Options
option(ENABLE_DEBUG "Enable debug build" OFF)
if(ENABLE_DEBUG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -DDEBUG")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic")

# Dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(UV REQUIRED libuv)
pkg_check_modules(OQS REQUIRED liboqs)
pkg_check_modules(SODIUM REQUIRED libsodium)
pkg_check_modules(OQS REQUIRED liboqs)
pkg_check_modules(SODIUM REQUIRED libsodium)

# --- Common Library ---
add_library(nasfs_common STATIC
    common/src/protocol.c
)
target_include_directories(nasfs_common PUBLIC
    common/include
    ${UV_INCLUDE_DIRS}
    ${OQS_INCLUDE_DIRS}
    ${SODIUM_INCLUDE_DIRS}
    ${OQS_INCLUDE_DIRS}
    ${SODIUM_INCLUDE_DIRS}
)
target_link_libraries(nasfs_common PUBLIC ${UV_LIBRARIES} ${OQS_LIBRARIES} ${SODIUM_LIBRARIES})
target_link_libraries(nasfs_common PUBLIC ${UV_LIBRARIES} ${OQS_LIBRARIES} ${SODIUM_LIBRARIES})

# --- Server Executable ---
add_executable(nasfs_server
    server/src/main.c
    server/src/config/config.c
    server/src/logging/log.c
    server/src/network/session.c
    server/src/utils/daemon.c
    server/src/utils/pid_file.c
    server/src/utils/signal_handler.c
)
target_include_directories(nasfs_server PRIVATE server/include)
target_link_directories(nasfs_server PRIVATE ${UV_LIBRARY_DIRS})
target_link_libraries(nasfs_server PRIVATE nasfs_common)

# --- Client Executable ---
add_executable(nasfs_client
    client/src/main.c
)
target_include_directories(nasfs_client PRIVATE client/include)
target_link_directories(nasfs_client PRIVATE ${UV_LIBRARY_DIRS})
target_link_libraries(nasfs_client PRIVATE nasfs_common)

# --- Testing ---
enable_testing()
add_test(NAME IntegrationTest COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_end_to_end.sh)
