cmake_minimum_required(VERSION 3.22)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -fPIC")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

find_program(CLANG_TIDY_EXE NAMES "clang-tidy")
set(CLANG_TIDY_COMMAND "${CLANG_TIDY_EXE}" "-checks=-*,modernize-*")

project(
    flowmeter
    VERSION 0.0.1
    LANGUAGES CXX
)

find_package(Python3 COMPONENTS Interpreter Development REQUIRED)
message(STATUS "Python3_INCLUDE_DIRS: ${Python3_INCLUDE_DIRS}")
message(STATUS "USE_PYTHON_INCLUDE_DIR: ${USE_PYTHON_INCLUDE_DIR}")

add_subdirectory(third-party)
include_directories(${FLOWMETER_INCLUDE_DIR})

set(LIBTINS_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/third-party/libtins/include")
set(FMT_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/third-party/fmt/include")
set(FLOWMETER_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/include")
set(CLI11_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/third-party/CLI11/include")
set(ABSEIL_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/third-party/absl")
set(FLOWMETER_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/include")
set(PYBIND11_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/third-party/pybind11/include")

set(LIBTINS_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/third-party/libtins/include")
set(LIBTINS_SO_LOC "${PROJECT_BINARY_DIR}/third-party/libtins/lib/libtins.so.4.6")
set_property(TARGET tins PROPERTY IMPORTED_LOCATION ${LIBTINS_SO_LOC})
add_subdirectory(src)
add_subdirectory(python)
