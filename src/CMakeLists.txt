add_executable(flow-meter "flow_meter.cpp")

target_include_directories(
    flow-meter PUBLIC
    ${FLOWMETER_INCLUDE_DIR}
    ${LIBTINS_INCLUDE_DIR}
    ${FMT_INCLUDE_DIR}
    ${CLI11_INCLUDE_DIR}
    ${ABSEIL_INCLUDE_DIR}
)
target_link_libraries(flow-meter PUBLIC ${LIBTINS_SO_LOC} fmt::fmt CLI11::CLI11 absl::flat_hash_map)
add_dependencies(flow-meter tins fmt CLI11)
set_target_properties(flow-meter PROPERTIES CXX_CLANG_TIDY "${CLANG_TIDY_COMMAND}")
