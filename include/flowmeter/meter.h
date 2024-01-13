#ifndef FLOWMETER_METER_H
#define FLOWMETER_METER_H

#include <iomanip>
#include <iostream>
#include "tins/ip.h"
#include "tins/ipv6.h"
#include "tins/packet.h"
#include "tins/sniffer.h"
#include "tins/tcp.h"
#include "tins/udp.h"
#include <map>

#include "flowmeter/constants.h"
#include "flowmeter/flow.h"

namespace Net {

class Meter {
  public:
    Meter(const std::string &input_file)
        : sniffer_(input_file), pcap_path_(input_file) {}

    void run() {
        std::cout << "Processing " << pcap_path_ << std::endl;
        Tins::Packet packet;
        auto start_time = std::chrono::high_resolution_clock::now();
        auto pkt_cnt = 0;
        while (packet = sniffer_.next_packet()) {
            pkt_cnt++;
        }
        auto end_time = std::chrono::high_resolution_clock::now();
        auto nanosecs = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            end_time - start_time)
                            .count();
        std::cout << nanosecs << std::endl;
        double seconds = nanosecs / 1'000'000'000.0;
        double pkts_per_sec = pkt_cnt / seconds;
        std::cout << "Read " << pkt_cnt << " packets in " << seconds
                  << " seconds" << std::endl;
        std::cout << std::setprecision(MAX_DOUBLE_PRECISION) << pkts_per_sec
                  << " pkts/sec" << std::endl;
    }

  private:
    Tins::FileSniffer sniffer_;
    std::string pcap_path_;
    std::map<FlowKey, Flow> flow_cache_;
};

} // end namespace Net

#endif
