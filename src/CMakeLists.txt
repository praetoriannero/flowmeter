set(LIBTINS_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/third-party/libtins/include")
set(FMT_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/third-party/fmt/include")
set(FLOWMETER_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/include")
set(CLI11_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/third-party/CLI11/include")
set(ABSEIL_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/third-party/absl")

add_executable(flow-meter "flow_meter.cpp")

target_include_directories(
    flow-meter PUBLIC
    ${LIBTINS_INCLUDE_DIR}
    ${FMT_INCLUDE_DIR}
    ${CLI11_INCLUDE_DIR}
    ${FLOWMETER_INCLUDE_DIR}
    ${ABSEIL_INCLUDE_DIR}
)
target_link_libraries(flow-meter PUBLIC ${LIBTINS_SO_LOC} fmt::fmt CLI11::CLI11)
add_dependencies(flow-meter tins fmt CLI11)
