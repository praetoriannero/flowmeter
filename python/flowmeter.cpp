#include <cstdint>
#include <flowmeter/meter.h>
#include <pybind11/pybind11.h>
#include <string>

namespace Net {

PYBIND11_MODULE(flowmeter, m) {
    m.doc() = "A python module to evaluate IP-based flows";
    pybind11::class_<Meter>(m, "Meter")
        .def(pybind11::init<const std::string &, const std::string &, const double &,
                            const double &>())
        .def("run", &Meter::run);
}

} // end namespace Net
