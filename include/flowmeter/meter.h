#ifndef FLOWMETER_METER_H
#define FLOWMETER_METER_H

#include <iomanip>
#include <iostream>
// #include "tins/ip.h"
// #include "tins/ipv6.h"
#include "tins/ethernetII.h"
#include "tins/packet.h"
#include "tins/sniffer.h"
// #include "tins/tcp.h"
// #include "tins/udp.h"
#include <map>

#include "flowmeter/constants.h"
#include "flowmeter/flow.h"

using high_resolution_clock = std::chrono::high_resolution_clock;

namespace Net {

template <typename IpVersion, typename TransportProto>
struct MeterImpl {

};

class Meter {
  public:
    Meter(const std::string &input_file)
        : sniffer_(input_file), pcap_path_(input_file) {}

    void run() {
        std::cout << "Processing " << pcap_path_ << std::endl;
        auto start_time = high_resolution_clock::now();
        auto pkt_cnt = 0;
        while (packet_ = sniffer_.next_packet()) {
            pkt_cnt++;

            eth_pdu_ = packet_.pdu()->find_pdu<Tins::EthernetII>();
            if (!eth_pdu_) {
                continue;
            }

            // get flow key

            // 
        }
        auto end_time = high_resolution_clock::now();
        auto nanosecs = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            end_time - start_time)
                            .count();
        std::cout << nanosecs << std::endl;
        seconds_ = nanosecs / 1'000'000'000.0;
        pkts_per_sec_ = pkt_cnt / seconds_;
        std::cout << "Read " << pkt_cnt << " packets in " << seconds_
                  << " seconds" << std::endl;
        std::cout << std::setprecision(MAX_DOUBLE_PRECISION) << pkts_per_sec_
                  << " pkts/sec" << std::endl;
    }

    void update(Tins::Packet& pkt) {
        // extract flow key
        // add to flow cache if not exist
    }

  private:
    Tins::Packet packet_;
    Tins::FileSniffer sniffer_;
    std::string pcap_path_;
    Tins::EthernetII* eth_pdu_;
    double seconds_;
    double pkts_per_sec_;
    // TO-DO: add types to FlowKey
    // TO-DO: add custom hashing function for FlowKey
    // std::map<FlowKey, Flow> flow_cache_;
};

} // end namespace Net

#endif
