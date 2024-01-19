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
    Meter(const std::string &input_file, const std::string &output_file)
        : sniffer_(input_file), pcap_path_(input_file), csv_path_(output_file) {}

    void run() {
        std::cout << "Processing " << pcap_path_ << std::endl;
        auto start_time = high_resolution_clock::now();
        auto pkt_count = 0;
        double last_packet_ts;
        double last_check;
        uint64_t init_id = 0;
        std::ofstream out_file(csv_path_);
        // std::cout << NetworkFlow::column_names() << std::endl;
        while (packet_ = sniffer_.next_packet()) {
            auto packet_ts = get_packet_timestamp(packet_);

            if (!pkt_count) {
                last_packet_ts = packet_ts;
                last_check = packet_ts;
            }
            pkt_count++;

            auto time_delta = packet_ts - last_check;

            if (time_delta > status_increment) {
                if (flow_cache_.size()) {
                    auto check_timeout = [packet_ts, &out_file](auto &it) {
                        auto time_since_start =
                            packet_ts - it.second.bidirectional.first_seen_ms;
                        auto time_since_update =
                            packet_ts - it.second.bidirectional.last_seen_ms;

                        if (time_since_start >= active_timeout_) {
                            // std::cout << "active timeout in cache check" << std::endl;
                            it.second.exp_code = ExpirationCode::ACTIVE_TIMEOUT;
                            out_file << it.second.to_string() << "\n";
                            auto last_init_id = it.second.init_id;
                            auto next_sub_init_id = it.second.sub_init_id++;
                            it.second =
                                NetworkFlow(it.first, last_init_id, next_sub_init_id);
                            return false;
                        } else if (time_since_update >= idle_timeout_) {
                            std::cout << "idle timeout" << std::endl;
                            it.second.exp_code = ExpirationCode::IDLE_TIMEOUT;
                            out_file << it.second.to_string() << "\n";
                            return true;
                        }

                        return false;
                    };

                    absl::erase_if(flow_cache_, check_timeout);
                }

                last_check = packet_ts;
            }

            ServicePair service_pair_{packet_};
            if (!service_pair_) {
                continue;
            }

            auto [it, success] = flow_cache_.emplace(
                service_pair_, NetworkFlow(service_pair_, init_id, default_sub_id));

            if (pkt_count == 1) {
                out_file << it->second.column_names() << "\n";
            }

            if (success) {
                init_id++;
            } else {
                if (packet_ts - it->second.bidirectional.last_seen_ms > active_timeout_) {
                    it->second.exp_code = ExpirationCode::ACTIVE_TIMEOUT;
                    out_file << it->second.to_string() << "\n";
                    auto last_init_id = it->second.init_id;
                    auto next_sub_init_id = it->second.sub_init_id++;
                    it->second =
                        NetworkFlow(service_pair_, last_init_id, next_sub_init_id);
                }
            }
            it->second.update(packet_, service_pair_, packet_ts);

            last_packet_ts = packet_ts;
        }

        out_file.close();

        // Display meter summary
        auto end_time = high_resolution_clock::now();
        auto nanosecs =
            std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time)
                .count();
        seconds_ = nanosecs / 1'000'000'000.0;
        pkts_per_sec_ = pkt_count / seconds_;
        std::cout << "Read " << pkt_count << " packets in " << seconds_ << " seconds"
                  << std::endl;
        std::cout << std::setprecision(MAX_DOUBLE_PRECISION) << pkts_per_sec_
                  << " pkts/sec" << std::endl;
    }

  private:
    Tins::Packet packet_;
    Tins::FileSniffer sniffer_;
    std::string pcap_path_;
    std::string csv_path_;
    double seconds_;
    double pkts_per_sec_;
    static constexpr double active_timeout_{120};
    static constexpr double idle_timeout_{60};
    static constexpr double status_increment{1};
    static constexpr u_int64_t default_sub_id{0};
    absl::node_hash_map<ServicePair, NetworkFlow> flow_cache_;
};

} // end namespace Net

#endif
