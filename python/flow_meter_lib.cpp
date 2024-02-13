#include <string>

#include <pybind11/pybind11.h>
#include <flowmeter/meter.h>


namespace Net {

PYBIND11_MODULE(flowmeter, m) {
    m.doc() = "A python module to evaluate IP-based flows";
    pybind11::class_<Meter>(m, "Meter")
        .def(pybind11::init<const std::string&, const std::string&>())
        .def("run", &Meter::run);
}

} // end namespace Net

