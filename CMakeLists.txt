cmake_minimum_required(VERSION 3.10)
project(nasfs VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic -g")

find_package(PkgConfig REQUIRED)
pkg_check_modules(UV REQUIRED libuv)

add_library(nasfs_common STATIC
    common/src/protocol.c
)
target_include_directories(nasfs_common PUBLIC
    common/include
    ${UV_INCLUDE_DIRS}
)
target_link_directories(nasfs_common PUBLIC ${UV_LIBRARY_DIRS})
target_link_libraries(nasfs_common PUBLIC ${UV_LIBRARIES})

add_executable(nasfs_server
    server/src/main.c
)
target_include_directories(nasfs_server PRIVATE server/include)
target_link_libraries(nasfs_server PRIVATE nasfs_common)

add_executable(nasfs_client
    client/src/main.c
)
target_include_directories(nasfs_client PRIVATE client/include)
target_link_libraries(nasfs_client PRIVATE nasfs_common)
