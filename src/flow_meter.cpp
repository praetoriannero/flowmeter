#include "CLI/CLI.hpp"
#include <chrono>
#include <cstdint>
#include <fmt/core.h>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>

#include "flowmeter/statistic.h"
#include "flowmeter/meter.h"

int main(int argc, char **argv) {
    CLI::App app{"A program to evaluate IP-based flows"};

    std::string pcap_path;
    std::string csv_path;
    app.add_option("-i,--input-path", pcap_path, "Path to .pcap/.pcapng file");
    app.add_option("-o,--output-path", csv_path, "Path to output .csv file");

    uint64_t init_val = 4;
    std::string feature_name = "test";
    auto stat = Statistic<uint64_t>(feature_name, init_val);
    uint64_t update_val = 5;
    stat.update(update_val);
    stat.update(update_val);
    std::cout << stat.to_string() << std::endl;

    CLI11_PARSE(app, argc, argv);

    Meter meter(pcap_path);

    meter.run();
    std::cout << "Done" << std::endl;
}
