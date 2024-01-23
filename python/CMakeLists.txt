# add_executable(
#     test-python
#     test_python.cpp
# )

pybind11_add_module(test_python test_python.cpp)

target_include_directories(
    test_python PUBLIC
    ${FLOWMETER_INCLUDE_DIR}
    ${Python3_INCLUDE_DIRS}
    ${PYBIND11_INCLUDE_DIR}
)
# target_link_libraries(
#     test-python PUBLIC pybind11::headers
# )