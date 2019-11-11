cmake_minimum_required(VERSION 3.6)
include(ExternalProject)

project(ocx-unicorn)

set(CAPSTONE_HOME $ENV{CAPSTONE_HOME})
if(NOT EXISTS ${CAPSTONE_HOME})
    set(CAPSTONE_HOME ${CMAKE_CURRENT_SOURCE_DIR}/capstone)
endif()
message(STATUS "Found CAPSTONE at " ${CAPSTONE_HOME})

set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "disable capstone defaults" FORCE)
set(CAPSTONE_ARM64_SUPPORT ON CACHE BOOL "enable capstone ARM64 support" FORCE)
set(CAPSTONE_ARM_SUPPORT ON CACHE BOOL "enable capstone ARM support" FORCE)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "disable capstone tests" FORCE)
add_subdirectory(${CAPSTONE_HOME} capstone EXCLUDE_FROM_ALL)

set_property(TARGET capstone-static PROPERTY POSITION_INDEPENDENT_CODE ON)


set(OCX_HOME $ENV{OCX_HOME})
if(NOT EXISTS ${OCX_HOME})
    set(OCX_HOME ${CMAKE_CURRENT_SOURCE_DIR}/ocx)
endif()
message(STATUS "Found OCX at " ${OCX_HOME})

set(OCX_BUILD_TESTS OFF CACHE BOOL "disable ocx tests" FORCE)
add_subdirectory(${OCX_HOME} ocx EXCLUDE_FROM_ALL)

set(UNICORN_HOME $ENV{UNICORN_HOME})
if(NOT EXISTS ${UNICORN_HOME})
    set(UNICORN_HOME ${CMAKE_CURRENT_SOURCE_DIR}/unicorn)
endif()
message(STATUS "Found UNICORN at " ${UNICORN_HOME})

if(CMAKE_BUILD_TYPE MATCHES DEBUG)
    set (UNICORN_DEBUG yes)
else()
    set (UNICORN_DEBUG no)
endif()
message(STATUS "Using UNICORN debug: " ${UNICORN_DEBUG})

ExternalProject_Add(unicorn-build
                    SOURCE_DIR "${UNICORN_HOME}"
                    BUILD_IN_SOURCE 1
                    CONFIGURE_COMMAND ""
                    BUILD_COMMAND make UNICORN_STATIC=yes UNICORN_DYNAMIC=no UNICORN_DEBUG=${UNICORN_DEBUG}
                    INSTALL_COMMAND "")
#set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES ${UNICORN_BIN})

set(CMAKE_CXX_STANDARD 11)

set(inc "${CMAKE_CURRENT_SOURCE_DIR}/ocx/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/capstone/include"
        "${UNICORN_HOME}/include")
set(src "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(sources "${src}/ocx-unicorn.cpp" "${src}/modeldb.cpp")


add_library(ocx-unicorn MODULE ${sources})
add_dependencies(ocx-unicorn unicorn-build ocx-test-runner ocx-dummy-core)
set_target_properties(ocx-unicorn PROPERTIES OUTPUT_NAME "ocx-qemu-arm")

target_include_directories(ocx-unicorn PUBLIC ${inc})
target_compile_options(ocx-unicorn PRIVATE -Werror -Wall)
target_link_libraries(ocx-unicorn ${UNICORN_HOME}/libunicorn.a capstone-static)

install(TARGETS ocx-unicorn DESTINATION lib)

enable_testing()
add_test(NAME ocx-unicorn
         COMMAND $<TARGET_FILE:ocx-test-runner>
                 $<TARGET_FILE:ocx-unicorn> Cortex-A53)
