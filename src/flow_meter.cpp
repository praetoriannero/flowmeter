#include "CLI/CLI.hpp"
#include <string>

#include "flowmeter/meter.h"

auto main(int argc, char **argv) -> int {
    CLI::App app{"A program to evaluate IP-based flows"};

    std::string pcap_path;
    std::string csv_path;
    double active_timeout{120};
    double idle_timeout{5};
    app.add_option("-i,--input-path", pcap_path, "Path to .pcap/.pcapng file")->required();
    app.add_option("-o,--output-path", csv_path, "Path to output .csv file")->required();
    app.add_option("--active-timeout", active_timeout,
                   "Active timeout duration in seconds")
        ->capture_default_str();
    app.add_option("--idle_timeout", idle_timeout, "Idle timeout duration in seconds")
        ->capture_default_str();
    CLI11_PARSE(app, argc, argv);

    Net::Meter meter(pcap_path, csv_path, active_timeout, idle_timeout);

    meter.run();
}
