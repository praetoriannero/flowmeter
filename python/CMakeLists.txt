pybind11_add_module(flowmeter flow_meter_lib.cpp)

target_include_directories(
    flowmeter PUBLIC
    ${FLOWMETER_INCLUDE_DIR}
    ${LIBTINS_INCLUDE_DIR}
    ${FMT_INCLUDE_DIR}
    ${CLI11_INCLUDE_DIR}
    ${ABSEIL_INCLUDE_DIR}
    ${Python3_INCLUDE_DIRS}
    ${PYBIND11_INCLUDE_DIR}
)
target_link_libraries(flowmeter PUBLIC ${LIBTINS_SO_LOC} fmt::fmt CLI11::CLI11 absl::flat_hash_map)
add_dependencies(flowmeter tins fmt CLI11)