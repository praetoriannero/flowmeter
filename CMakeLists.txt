cmake_minimum_required(VERSION 3.22)

project(
    flowmeter
    VERSION 0.0.1
    LANGUAGES CXX
)

add_subdirectory(third-party)
# find_package(PCAP REQUIRED)

set(FLOWMETER_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/include/flowmeter")
include_directories(${FLOWMETER_INCLUDE_DIR})

set(LIBTINS_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/third-party/libtins/include")
# message(STATUS "libtins include dir - ${LIBTINS_INCLUDE_DIR}")
set(LIBTINS_SO_LOC "${PROJECT_BINARY_DIR}/third-party/libtins/lib/libtins.so.4.6")
# message(STATUS "libtins.so - ${LIBTINS_SO_LOC}")
set_property(TARGET tins PROPERTY IMPORTED_LOCATION ${LIBTINS_SO_LOC})
add_subdirectory(src)
