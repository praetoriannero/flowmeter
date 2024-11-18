#ifndef FLOWMETER_METER_H
#define FLOWMETER_METER_H

#include "absl/container/flat_hash_map.h"
#include "tins/ethernetII.h"
#include "tins/ip.h"
#include "tins/ipv6.h"
#include "tins/packet.h"
#include "tins/sniffer.h"
#include "tins/tcp.h"
#include "tins/udp.h"
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>

#include "flowmeter/constants.h"
#include "flowmeter/flow.h"

using high_resolution_clock = std::chrono::high_resolution_clock;

namespace Net {

template <typename IpVersion, typename TransportProto>
struct MeterImpl {};

class Meter {
  public:
    Meter(const std::string &input_file, const std::string &output_file,
          const double &active_timeout, const double &idle_timeout)
        : sniffer_(input_file), pcap_path_(input_file), csv_path_(output_file),
          active_timeout_(active_timeout), idle_timeout_(idle_timeout) {}

    void run() {
        std::cout << "Processing " << pcap_path_ << std::endl;
        auto start_time = high_resolution_clock::now();
        auto pkt_count = 0;
        double last_packet_ts;
        double last_check;
        uint64_t init_id = 0;
        std::ofstream out_file(csv_path_);

        // TODO: create header in CSV file before starting this loop

        while (packet_ = sniffer_.next_packet()) {
            auto packet_ts = get_packet_timestamp(packet_);

            if (!pkt_count) {
                last_packet_ts = packet_ts;
                last_check = packet_ts;
            }

            pkt_count++;

            auto time_delta = packet_ts - last_check;

            if (time_delta > status_increment_) {
                if (flow_cache_.size()) {
                    auto check_timeout = [packet_ts, &out_file, this](auto &it) {
                        auto time_since_start =
                            packet_ts - it.second.bidirectional.first_seen_ms;
                        auto time_since_update =
                            packet_ts - it.second.bidirectional.last_seen_ms;

                        if (time_since_start >= this->active_timeout_) {
                            it.second.exp_code = ExpirationCode::ACTIVE_TIMEOUT;
                            it.second.finalize();
                            out_file << it.second.to_string() << "\n";
                            it.second.sub_init_id++;
                            it.second.exp_code = ExpirationCode::ALIVE;
                            it.second.reset();
                            return false;
                        } else if (time_since_update >= this->idle_timeout_) {
                            it.second.exp_code = ExpirationCode::IDLE_TIMEOUT;
                            it.second.finalize();
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
                service_pair_, NetworkFlow(service_pair_, init_id, default_sub_id_));

            if (pkt_count == 1) {
                out_file << it->second.column_names() << "\n";
            }

            if (success) {
                init_id++;
            }

            it->second.update(packet_, service_pair_, packet_ts);

            last_packet_ts = packet_ts;
        }

        for (auto &[key, flow] : flow_cache_) {
            flow.exp_code = ExpirationCode::SESSION_END;
            out_file << flow.to_string() << "\n";
        }
        flow_cache_.clear();

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
    double active_timeout_;
    double idle_timeout_;
    static constexpr double status_increment_{1};
    static constexpr u_int64_t default_sub_id_{0};
    absl::flat_hash_map<ServicePair, NetworkFlow> flow_cache_;
};

} // end namespace Net

#endif
