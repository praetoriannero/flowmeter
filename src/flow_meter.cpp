#include "CLI/CLI.hpp"
#include "tins/ip.h"
#include "tins/ipv6.h"
#include "tins/packet.h"
#include "tins/sniffer.h"
#include "tins/tcp.h"
#include "tins/udp.h"
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

uint32_t MAX_DOUBLE_PRECISION = std::numeric_limits<double>::digits10 + 1;

enum ExpirationCode { ALIVE, ACTIVE_TIMEOUT, IDLE_TIMEOUT, USER_SPECIFIED };

struct FlowKey {
    // FlowKey()
};

template <typename T>
struct Statistic {
    std::string name;
    T min;
    T max;
    T count;
    double mean;
    double stddev = 0;

    Statistic(std::string &stat_name, T &init_val)
        : name(stat_name), min(init_val), max(init_val), mean(init_val),
          count(1) {}

    void update(T &val) {
        count++;
        min = val < min ? val : min;
        max = val > max ? val : max;
        auto tmp_mean = mean;
        mean += (val - tmp_mean) / count;
        stddev += (val - tmp_mean) * (val - mean);
    }

    std::string header() {
        std::stringstream ss;
        ss << name << "_min," << name << "_max," << name << "_mean," << name
           << "_stddev,";
        return ss.str();
    }

    std::string to_string() {
        std::stringstream ss;
        ss << min << "," << max << ","
           << std::setprecision(MAX_DOUBLE_PRECISION) << mean << ","
           << std::setprecision(MAX_DOUBLE_PRECISION) << stddev;
        return ss.str();
    }
};

struct NetNode {
    // counts for incoming/outgoing ports
    uint64_t inc_port;
    uint64_t out_port;

    // pe = port entropy
    double inc_pe;
    double out_pe;

    uint64_t udp_count;
    uint64_t tcp_count;

    uint64_t ip_count;
    uint64_t ip6_count;

    uint64_t nontransport_count;

    uint64_t degree;

    uint64_t min_peer_degree;
    uint64_t max_peer_degree;
    double mean_peer_degree;
    double stddev_peer_degree;

    // bytes per second per peer connection
    // edge weights-ish
    uint64_t min_data_flow;
    uint64_t max_data_flow;
    double mean_data_rate;
    double stddev_data_rate;

    // num node pairs in neighborhood / total pairs
    double connectivity;
};

struct Flow {
    uint64_t first_seen_ns;
    uint64_t last_seen_ns;
    uint64_t duration_ns;
    uint64_t pkt_count = 0;
    uint64_t byte_count = 0;

    uint64_t min_ps;
    uint64_t max_ps;
    double mean_ps;
    double stddev_ps = 0;

    uint64_t min_piat_ns;
    uint64_t max_piat_ns;
    double mean_piat_ns;
    double stddev_piat_ns = 0;

    double min_entropy;
    double max_entropy;
    double mean_entropy;
    double stddev_entropy = 0;

    uint64_t syn_count = 0;
    uint64_t cwr_count = 0;
    uint64_t ece_count = 0;
    uint64_t urg_count = 0;
    uint64_t ack_count = 0;
    uint64_t psh_count = 0;
    uint64_t rst_count = 0;
    uint64_t fin_count = 0;

    Flow(Tins::Packet &pkt) {
        auto pkt_size = pkt.pdu()->size();
        min_ps = pkt_size;
        max_ps = pkt_size;
        mean_ps = pkt_size;
    }
};

struct NetworkFlow {
    NetworkFlow(int64_t active_timeout, int64_t idle_timeout)
        : active_timeout_(active_timeout), idle_timeout_(idle_timeout) {}

    void update(Tins::Packet &pkt) { auto tmp = pkt; }

    // void add_field(std::string field_name, )

    // auto flow_feature_count = 0;

    int64_t init_id_{};
    int64_t sub_init_id{};

    ExpirationCode exp_reason{};

    std::string src_mac_{};
    std::string dst_mac_{};

    std::string src_ip_{};
    std::string dst_ip_{};

    uint16_t ip_version_{};

    uint16_t src_port_{};
    uint16_t dst_port_{};

    uint16_t vlan_id_{};
    uint16_t transport_proto_{};

    int64_t active_timeout_{};
    int64_t idle_timeout_{};
};

class Reader {
  public:
    Reader(const std::string &input_file)
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
        fmt::print("{}\n", seconds);
        double pkts_per_sec = pkt_cnt / seconds;
        std::cout << "Read " << pkt_cnt << " packets in " << seconds
                  << " seconds" << std::endl;
        std::cout << std::setprecision(MAX_DOUBLE_PRECISION) << pkts_per_sec
                  << " pkts/sec" << std::endl;
    }

  private:
    Tins::FileSniffer sniffer_;
    std::string pcap_path_;
};

int main(int argc, char **argv) {
    CLI::App app{"A program to evaluate IP-based flows"};

    std::string pcap_path;
    std::string csv_path;
    app.add_option("-i,--input-path", pcap_path, "Path to .pcap/.pcapng file");
    app.add_option("-o,--output-path", csv_path, "Path to output .csv file");

    auto i = []() { return 1; };

    uint64_t init_val = 4;
    std::string feature_name = "test";
    auto stat = Statistic<uint64_t>(feature_name, init_val);
    uint64_t update_val = 5;
    stat.update(update_val);
    stat.update(update_val);
    std::cout << stat.to_string() << std::endl;

    CLI11_PARSE(app, argc, argv);

    Reader reader(pcap_path);

    // reader.run();
    std::cout << "Done" << std::endl;
}
