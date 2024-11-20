pybind11_add_module(pyflowmeter flowmeter.cpp)

target_include_directories(
    pyflowmeter PUBLIC
    ${FLOWMETER_INCLUDE_DIR}
    ${LIBTINS_INCLUDE_DIR}
    ${FMT_INCLUDE_DIR}
    ${CLI11_INCLUDE_DIR}
    ${ABSEIL_INCLUDE_DIR}
    ${Python3_INCLUDE_DIRS}
    ${PYBIND11_INCLUDE_DIR}
)
target_link_libraries(pyflowmeter PUBLIC ${LIBTINS_SO_LOC} fmt::fmt CLI11::CLI11 absl::flat_hash_map)
add_dependencies(pyflowmeter tins fmt CLI11)