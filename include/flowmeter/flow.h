#ifndef FLOWMETER_FLOW_H
#define FLOWMETER_FLOW_H

#include "tins/ip.h"
#include "tins/ipv6.h"
#include "tins/packet.h"
#include "tins/sniffer.h"
#include "tins/tcp.h"
#include "tins/udp.h"
#include <cstdint>

namespace Net {

enum ExpirationCode { ALIVE, ACTIVE_TIMEOUT, IDLE_TIMEOUT, USER_SPECIFIED };

struct FlowKey {
    // FlowKey()
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
    NetworkFlow(int64_t active_timeout_val, int64_t idle_timeout_val)
        : active_timeout(active_timeout_val), idle_timeout(idle_timeout_val) {}

    void update(Tins::Packet &pkt) { auto tmp = pkt; }

    // void add_field(std::string field_name, )

    // auto flow_feature_count = 0;

    int64_t init_id{};
    int64_t sub_init_id{};

    ExpirationCode exp_reason{};

    std::string src_mac{};
    std::string dst_mac{};

    std::string src_ip{};
    std::string dst_ip{};

    uint16_t ip_version{};

    uint16_t src_port{};
    uint16_t dst_port{};

    uint16_t vlan_id{};
    uint16_t transport_proto{};

    int64_t active_timeout{};
    int64_t idle_timeout{};
};

}

#endif
