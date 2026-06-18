cmake_minimum_required(VERSION 3.16)
project(nasfs VERSION 0.1.0 LANGUAGES C)

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_definitions(_POSIX_C_SOURCE=200809L)

option(ENABLE_DEBUG "Enable debug build" OFF)
option(NASFS_INSTALL_SYSTEMD "Install the systemd unit" ON)
option(NASFS_ENABLE_SANITIZERS
       "Enable address and undefined behavior sanitizers" OFF)
set(NASFS_SYSTEMD_UNIT_DIR "${CMAKE_INSTALL_LIBDIR}/systemd/system"
    CACHE PATH "Directory for installing systemd service units")

if(ENABLE_DEBUG)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -DDEBUG")
else()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic")

if(NASFS_ENABLE_SANITIZERS)
  if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  else()
    message(FATAL_ERROR "Sanitizers are only supported with Clang or GCC")
  endif()
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(UV REQUIRED libuv)
pkg_check_modules(OQS REQUIRED liboqs)
pkg_check_modules(SODIUM REQUIRED libsodium)
pkg_check_modules(OPENSSL REQUIRED openssl)

set(NASFS_BINDIR "${CMAKE_INSTALL_FULL_BINDIR}")
set(NASFS_SYSCONFDIR "${CMAKE_INSTALL_FULL_SYSCONFDIR}/nasfs")
set(NASFS_LOCALSTATEDIR "${CMAKE_INSTALL_FULL_LOCALSTATEDIR}")

configure_file(utils/nasfsctl.in ${CMAKE_CURRENT_BINARY_DIR}/nasfsctl @ONLY)
configure_file(systemd/nasfs.service.in ${CMAKE_CURRENT_BINARY_DIR}/nasfs.service
               @ONLY)

add_library(nasfs_common STATIC
  common/src/protocol.c
  common/src/handshake.c
  common/src/auth.c
  common/src/ecc.c
  common/src/crypto_engine.c
  common/src/pake.c
)
target_include_directories(nasfs_common PUBLIC
  common/include
  ${UV_INCLUDE_DIRS}
  ${OQS_INCLUDE_DIRS}
  ${SODIUM_INCLUDE_DIRS}
  ${OPENSSL_INCLUDE_DIRS}
)
target_link_directories(nasfs_common PUBLIC
  ${UV_LIBRARY_DIRS}
  ${OQS_LIBRARY_DIRS}
  ${SODIUM_LIBRARY_DIRS}
  ${OPENSSL_LIBRARY_DIRS}
)
target_compile_options(nasfs_common PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(nasfs_common PUBLIC
  ${UV_LIBRARIES}
  ${OQS_LIBRARIES}
  ${SODIUM_LIBRARIES}
  ${OPENSSL_LIBRARIES}
)

add_executable(nasfs_server
  server/src/main.c
  server/src/config/config.c
  server/src/logging/log.c
  server/src/network/session.c
  server/src/utils/daemon.c
  server/src/utils/pid_file.c
  server/src/utils/signal_handler.c
)
target_include_directories(nasfs_server PRIVATE server/include common/include)
target_compile_options(nasfs_server PRIVATE -Wall -Wextra -Wpedantic)
target_link_directories(nasfs_server PRIVATE
  ${UV_LIBRARY_DIRS}
  ${OQS_LIBRARY_DIRS}
  ${SODIUM_LIBRARY_DIRS}
  ${OPENSSL_LIBRARY_DIRS}
)
target_link_libraries(nasfs_server PRIVATE nasfs_common ${OPENSSL_LIBRARIES})

add_executable(nasfs_client
  client/src/main.c
)
target_include_directories(nasfs_client PRIVATE client/include common/include)
target_compile_options(nasfs_client PRIVATE -Wall -Wextra -Wpedantic)
target_link_directories(nasfs_client PRIVATE
  ${UV_LIBRARY_DIRS}
  ${OQS_LIBRARY_DIRS}
  ${SODIUM_LIBRARY_DIRS}
  ${OPENSSL_LIBRARY_DIRS}
)
target_link_libraries(nasfs_client PRIVATE nasfs_common ${OPENSSL_LIBRARIES})

enable_testing()

add_executable(test_handshake tests/test_handshake.c)
target_include_directories(test_handshake PRIVATE common/include)
target_compile_options(test_handshake PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(test_handshake PRIVATE nasfs_common)

add_executable(test_config tests/test_config.c server/src/config/config.c)
target_include_directories(test_config PRIVATE server/include common/include)
target_compile_options(test_config PRIVATE -Wall -Wextra -Wpedantic)

add_executable(test_auth tests/test_auth.c)
target_include_directories(test_auth PRIVATE common/include)
target_compile_options(test_auth PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(test_auth PRIVATE nasfs_common)

add_executable(test_encryption tests/test_encryption.c)
target_include_directories(test_encryption PRIVATE common/include)
target_compile_options(test_encryption PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(test_encryption PRIVATE nasfs_common)

add_executable(test_ecc tests/test_ecc.c)
target_include_directories(test_ecc PRIVATE common/include)
target_compile_options(test_ecc PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(test_ecc PRIVATE nasfs_common)

add_executable(test_pake tests/test_pake.c)
target_include_directories(test_pake PRIVATE common/include)
target_compile_options(test_pake PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(test_pake PRIVATE nasfs_common)

add_executable(benchmark tests/benchmark.c)
target_include_directories(benchmark PRIVATE common/include)
target_compile_options(benchmark PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(benchmark PRIVATE nasfs_common)

add_executable(nasfs_optimizer utils/nasfs_optimizer.c)
target_include_directories(nasfs_optimizer PRIVATE
    ${UV_INCLUDE_DIRS} ${SODIUM_INCLUDE_DIRS})
target_link_directories(nasfs_optimizer PRIVATE
    ${UV_LIBRARY_DIRS} ${SODIUM_LIBRARY_DIRS})
target_link_libraries(nasfs_optimizer PRIVATE
    ${UV_LIBRARIES} ${SODIUM_LIBRARIES})

add_test(NAME unit_handshake COMMAND test_handshake)
add_test(NAME unit_config COMMAND test_config)
add_test(NAME unit_auth COMMAND test_auth)
add_test(NAME unit_encryption COMMAND test_encryption)
add_test(NAME unit_ecc COMMAND test_ecc)
add_test(NAME unit_pake COMMAND test_pake)
add_test(NAME integration_e2e COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_end_to_end.sh)
set_tests_properties(
  integration_e2e
  PROPERTIES
  ENVIRONMENT
    "NASFS_SERVER_BIN=$<TARGET_FILE:nasfs_server>;NASFS_CLIENT_BIN=$<TARGET_FILE:nasfs_client>;NASFS_TEST_ROOT=${CMAKE_CURRENT_BINARY_DIR}/tests-workspace;NASFS_STORAGE_DIR=${CMAKE_CURRENT_BINARY_DIR}/storage"
)

add_test(NAME integration_encryption COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_file_encryption.sh)
set_tests_properties(
  integration_encryption
  PROPERTIES
  ENVIRONMENT
    "NASFS_SERVER_BIN=$<TARGET_FILE:nasfs_server>;NASFS_CLIENT_BIN=$<TARGET_FILE:nasfs_client>;NASFS_TEST_ROOT=${CMAKE_CURRENT_BINARY_DIR}/tests-workspace-enc;NASFS_STORAGE_DIR=${CMAKE_CURRENT_BINARY_DIR}/storage-enc"
)

install(TARGETS nasfs_server nasfs_client
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/nasfsctl
  DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(FILES server/config/nasfs.conf
  DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/nasfs
)

if(NASFS_INSTALL_SYSTEMD)
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/nasfs.service
    DESTINATION ${NASFS_SYSTEMD_UNIT_DIR}
  )
endif()

install(DIRECTORY DESTINATION ${CMAKE_INSTALL_LOCALSTATEDIR}/run/nasfs)
install(DIRECTORY DESTINATION ${CMAKE_INSTALL_LOCALSTATEDIR}/log/nasfs)
