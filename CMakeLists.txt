cmake_minimum_required(VERSION 3.22)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -std=c++17 -fPIC")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

project(
    flowmeter
    VERSION 0.0.1
    LANGUAGES CXX
)

add_subdirectory(third-party)

set(FLOWMETER_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/include/flowmeter")
include_directories(${FLOWMETER_INCLUDE_DIR})

set(LIBTINS_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/third-party/libtins/include")
set(LIBTINS_SO_LOC "${PROJECT_BINARY_DIR}/third-party/libtins/lib/libtins.so.4.6")
set_property(TARGET tins PROPERTY IMPORTED_LOCATION ${LIBTINS_SO_LOC})
add_subdirectory(src)
