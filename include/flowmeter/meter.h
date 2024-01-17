#ifndef FLOWMETER_METER_H
#define FLOWMETER_METER_H

#include "absl/container/node_hash_map.h"
#include "tins/ethernetII.h"
#include "tins/ip.h"
#include "tins/ipv6.h"
#include "tins/packet.h"
#include "tins/sniffer.h"
#include "tins/tcp.h"
#include "tins/udp.h"
#include <iomanip>
#include <iostream>

#include "flowmeter/constants.h"
#include "flowmeter/flow.h"

using high_resolution_clock = std::chrono::high_resolution_clock;

namespace Net {

template <typename IpVersion, typename TransportProto>
struct MeterImpl {};

class Meter {
  public:
    Meter(const std::string &input_file)
        : sniffer_(input_file), pcap_path_(input_file) {}

    void run() {
        std::cout << "Processing " << pcap_path_ << std::endl;
        auto start_time = high_resolution_clock::now();
        auto pkt_count = 0;
        double last_packet_ts;
        double last_check;
        while (packet_ = sniffer_.next_packet()) {
            auto packet_ts = get_packet_timestamp(packet_);

            if (!pkt_count) {
                last_packet_ts = packet_ts;
                last_check = packet_ts;
            }

            auto time_delta = packet_ts - last_check;
            pkt_count++;

            if (time_delta > status_increment) {
                if (flow_cache_.size()) {
                    auto check_timeout = [packet_ts](auto &it) {
                        auto time_since_start =
                            packet_ts - it.second.bidirectional.last_seen_ms;
                        auto time_since_update =
                            packet_ts - it.second.bidirectional.last_seen_ms;

                        if (time_since_start >= active_timeout_) {
                            it.second.exp_code = ExpirationCode::ACTIVE_TIMEOUT;
                            return true;
                        } else if (time_since_update >= idle_timeout_) {
                            it.second.exp_code = ExpirationCode::IDLE_TIMEOUT;
                            return true;
                        }

                        return false;
                    };

                    absl::erase_if(flow_cache_, check_timeout);
                }

                last_check = packet_ts;
            }

            ServicePair services_{packet_};
            if (!services_) {
                continue;
            }
            auto [it, success] = flow_cache_.emplace(services_, NetworkFlow(services_));

            it->second.update(packet_, services_, packet_ts);

            last_packet_ts = packet_ts;
        }

        // Display meter summary
        auto end_time = high_resolution_clock::now();
        auto nanosecs = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            end_time - start_time)
                            .count();
        seconds_ = nanosecs / 1'000'000'000.0;
        pkts_per_sec_ = pkt_count / seconds_;
        std::cout << "Read " << pkt_count << " packets in " << seconds_
                  << " seconds" << std::endl;
        std::cout << std::setprecision(MAX_DOUBLE_PRECISION) << pkts_per_sec_
                  << " pkts/sec" << std::endl;
    }

  private:
    Tins::Packet packet_;
    Tins::FileSniffer sniffer_;
    std::string pcap_path_;
    double seconds_;
    double pkts_per_sec_;
    static constexpr double active_timeout_{120};
    static constexpr double idle_timeout_{60};
    static constexpr double status_increment{1};
    absl::node_hash_map<ServicePair, NetworkFlow> flow_cache_;
};

} // end namespace Net

#endif
