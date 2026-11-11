cmake_minimum_required(VERSION 3.16)
project(pathguard VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

add_compile_options(-Wall -Wextra -fstack-protector-strong)
add_link_options(-pie -Wl,-z,relro,-z,now)

find_package(PkgConfig REQUIRED)
pkg_check_modules(YARA REQUIRED IMPORTED_TARGET yara)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(Threads REQUIRED)

add_library(pathguard_core STATIC
  src/common/audit_log.cpp
  src/common/config.cpp
  src/common/fdpass.cpp
  src/common/hashlist.cpp
  src/common/json.cpp
  src/common/sha256.cpp
  src/common/util.cpp
  src/policy/policy.cpp
  src/quarantine/store.cpp
  src/scanner/scanner.cpp
)
target_include_directories(pathguard_core PUBLIC src)
target_compile_definitions(pathguard_core PUBLIC _GNU_SOURCE PATHGUARD_VERSION="${PROJECT_VERSION}")
target_link_libraries(pathguard_core PUBLIC PkgConfig::YARA OpenSSL::Crypto Threads::Threads)

add_executable(pathguardd
  src/agent/main.cpp
  src/agent/agent.cpp
  src/agent/control.cpp
  src/agent/quarantine_worker.cpp
  src/agent/worker_main.cpp
)
target_link_libraries(pathguardd PRIVATE pathguard_core)

add_executable(pathguardctl src/cli/main.cpp)
target_link_libraries(pathguardctl PRIVATE pathguard_core)

include(CTest)
if(BUILD_TESTING)
  add_executable(pathguard_unit_tests tests/unit/unit_tests.cpp)
  target_link_libraries(pathguard_unit_tests PRIVATE pathguard_core)
  add_test(NAME unit COMMAND pathguard_unit_tests)
endif()

install(TARGETS pathguardd pathguardctl RUNTIME DESTINATION sbin)
