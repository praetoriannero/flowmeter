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

    CLI11_PARSE(app, argc, argv);

    Net::Meter meter(pcap_path);

    meter.run();
}

