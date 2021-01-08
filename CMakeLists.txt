cmake_minimum_required(VERSION 3.6)
include(ExternalProject)

project(ocx-qemu-arm)

set(CMAKE_CXX_STANDARD 11)

set(CAPSTONE_HOME $ENV{CAPSTONE_HOME})
if(NOT EXISTS ${CAPSTONE_HOME})
    set(CAPSTONE_HOME ${CMAKE_CURRENT_SOURCE_DIR}/capstone)
endif()

set(OCX_HOME $ENV{OCX_HOME})
if(NOT EXISTS ${OCX_HOME})
    set(OCX_HOME ${CMAKE_CURRENT_SOURCE_DIR}/ocx)
endif()

set(UNICORN_HOME $ENV{UNICORN_HOME})
if(NOT EXISTS ${UNICORN_HOME})
    set(UNICORN_HOME ${CMAKE_CURRENT_SOURCE_DIR}/unicorn)
endif()

if(CMAKE_BUILD_TYPE MATCHES DEBUG)
    set (UNICORN_DEBUG yes)
else()
    set (UNICORN_DEBUG no)
endif()

message(STATUS "Found CAPSTONE at " ${CAPSTONE_HOME})
message(STATUS "Found OCX at " ${OCX_HOME})
message(STATUS "Found UNICORN at " ${UNICORN_HOME})
message(STATUS "Using UNICORN debug: " ${UNICORN_DEBUG})

set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "disable capstone defaults" FORCE)
set(CAPSTONE_ARM64_SUPPORT ON CACHE BOOL "enable capstone ARM64 support" FORCE)
set(CAPSTONE_ARM_SUPPORT ON CACHE BOOL "enable capstone ARM support" FORCE)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "disable capstone tests" FORCE)
add_subdirectory(${CAPSTONE_HOME} capstone EXCLUDE_FROM_ALL)
set_property(TARGET capstone-static PROPERTY POSITION_INDEPENDENT_CODE ON)

set(OCX_BUILD_TESTS OFF CACHE BOOL "disable ocx tests" FORCE)

add_subdirectory(${OCX_HOME} ocx EXCLUDE_FROM_ALL)

set(inc "${OCX_HOME}/include"
        "${CAPSTONE_HOME}/include"
        "${UNICORN_HOME}/include")
set(src "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(sources "${src}/armcore.cpp" "${src}/modeldb.cpp")

add_library(ocx-qemu-arm MODULE ${sources})

if (MSVC)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    set(UNICORN_LIB ${UNICORN_HOME}/prebuilt/libunicorn.a
                    ${UNICORN_HOME}/prebuilt/libgcc.a
                    ${UNICORN_HOME}/prebuilt/libmingw32.a
                    ${UNICORN_HOME}/prebuilt/libmingwex.a)
else()
    ExternalProject_Add(unicorn-build
                        SOURCE_DIR "${UNICORN_HOME}"
                        BUILD_IN_SOURCE 1
                        CONFIGURE_COMMAND ""
                        BUILD_COMMAND make UNICORN_STATIC=yes UNICORN_DYNAMIC=no UNICORN_DEBUG=${UNICORN_DEBUG}
                        INSTALL_COMMAND "")
    add_dependencies(ocx-qemu-arm unicorn-build)
    set(UNICORN_LIB ${UNICORN_HOME}/libunicorn.a)
endif()

add_dependencies( ocx-qemu-arm ocx-test-runner ocx-dummy-core)

target_include_directories(ocx-qemu-arm PRIVATE ${inc})

if (MSVC)
    # warning level 3 and all warnings as errors
    target_compile_options(ocx-qemu-arm PRIVATE /W3 /WX)
else()
    # lots of warnings and all warnings as errors
    target_compile_options(ocx-qemu-arm PRIVATE -Werror -Wall -Wextra)
endif()

target_link_libraries(ocx-qemu-arm ${UNICORN_LIB} capstone-static)

install(TARGETS ocx-qemu-arm DESTINATION lib)

enable_testing()
add_test(NAME ocx-qemu-arm
         COMMAND $<TARGET_FILE:ocx-test-runner>
                 $<TARGET_FILE:ocx-qemu-arm> Cortex-A53)
