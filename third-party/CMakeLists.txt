message(STATUS "Looking for libpcap...")
include(FindPCAP.cmake)
if (PCAP_FOUND)
    message(STATUS "libpcap FOUND")
else()
    message(FATAL_ERROR "libpcap NOT FOUND")
endif()

message(STATUS "Loading library libtins...")
set(CMAKE_DISABLE_FIND_PACKAGE_Boost TRUE)
set(CMAKE_DISABLE_FIND_PACKAGE_Doxygen TRUE)
add_subdirectory(libtins)
message(STATUS "libtins loaded.")

message(STATUS "Loading library pybind11...")
add_subdirectory(pybind11)
message(STATUS "pybind11 loaded.")

message(STATUS "Loading library fmt...")
add_subdirectory(fmt)
message(STATUS "fmt loaded.")

message(STATUS "Loading library CLI11...")
add_subdirectory(CLI11)
message(STATUS "CLI11 loaded.")

message(STATUS "Loading library abseil-cpp...")
add_subdirectory(absl)
message(STATUS "abseil-cpp loaded.")
