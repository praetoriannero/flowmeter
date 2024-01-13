#ifndef FLOWMETER_FLOW_H
#define FLOWMETER_FLOW_H

#include "tins/hw_address.h"
#include "tins/ip_address.h"
#include "tins/ipv6_address.h"
#include "tins/ip.h"
#include "tins/ipv6.h"
#include "tins/packet.h"
#include "tins/tcp.h"
#include "tins/udp.h"
#include <cstdint>

#include "flowmeter/statistic.h"
#include "flowmeter/utils.h"

namespace Net {

enum ExpirationCode { ALIVE, ACTIVE_TIMEOUT, IDLE_TIMEOUT, USER_SPECIFIED };

using MacAddress = Tins::HWAddress<6>;

template <typename IpAddress>
struct FlowKey {
    MacAddress l_mac_addr;
    MacAddress r_mac_addr;
    IpAddress l_ip_addr;
    IpAddress r_ip_addr;
    uint16_t l_port;
    uint16_t r_port;
    uint8_t vlan_id;
    uint8_t transport_proto;
};

struct Flow {
    std::string direction;
    double first_seen_ms = 0;
    double last_seen_ms = 0;
    double duration_ms = 0;
    uint64_t pkt_count = 0;
    uint64_t byte_count = 0;
    Statistic<uint64_t> packet_size{"ps"};   // packet size
    Statistic<double> packet_iat{"piat"};    // packet inter-arrival time
    // Statistic<double> packet_entropy{"entropy", 0.0};
    uint64_t syn_count = 0;
    uint64_t cwr_count = 0;
    uint64_t ece_count = 0;
    uint64_t urg_count = 0;
    uint64_t ack_count = 0;
    uint64_t psh_count = 0;
    uint64_t rst_count = 0;
    uint64_t fin_count = 0;

    Flow(std::string direction_) : direction(direction_) {}

    void update(Tins::Packet &packet) {
        auto pkt_timestamp = get_packet_timestamp(packet);
        auto pkt_byte_count = packet.pdu()->size();
        pkt_count++;

        first_seen_ms = pkt_timestamp < first_seen_ms ? pkt_timestamp : first_seen_ms;
        auto tmp_last_seen_ms = last_seen_ms;
        last_seen_ms = pkt_timestamp > last_seen_ms ? pkt_timestamp : last_seen_ms;
        
        byte_count += pkt_byte_count;

        packet_size.update(byte_count);

        if (pkt_count > 1) {
            auto time_delta = last_seen_ms - tmp_last_seen_ms;
            packet_iat.update(time_delta);
        }
    }

    void finalize() {
        duration_ms = last_seen_ms - first_seen_ms;
    }

    void update(Tins::Packet &packet, Tins::TCP &tcp_pdu) {
        if (tcp_pdu.get_flag(Tins::TCP::SYN)) { syn_count++; }
        if (tcp_pdu.get_flag(Tins::TCP::CWR)) { cwr_count++; }
        if (tcp_pdu.get_flag(Tins::TCP::ECE)) { ece_count++; }
        if (tcp_pdu.get_flag(Tins::TCP::URG)) { urg_count++; }
        if (tcp_pdu.get_flag(Tins::TCP::ACK)) { ack_count++; }
        if (tcp_pdu.get_flag(Tins::TCP::PSH)) { psh_count++; }
        if (tcp_pdu.get_flag(Tins::TCP::RST)) { rst_count++; }
        if (tcp_pdu.get_flag(Tins::TCP::FIN)) { fin_count++; }
    }

    std::string to_string() {
        return "NOT IMPLEMENTED";
    }
};

template <typename IpVersion, typename TransportProto>
struct NetworkFlow {
    NetworkFlow(int64_t active_timeout_val, int64_t idle_timeout_val)
        : active_timeout(active_timeout_val), idle_timeout(idle_timeout_val) {}

    void update(Tins::Packet &pkt) {

    }

    // void add_field(std::string field_name, )

    // auto flow_feature_count = 0;

    int64_t init_id{};
    int64_t sub_init_id{};

    ExpirationCode exp_code{};

    std::string src_mac{};
    std::string dst_mac{};

    IpVersion src_ip{};
    IpVersion dst_ip{};

    uint16_t ip_version{};

    uint16_t src_port{};
    uint16_t dst_port{};

    uint16_t vlan_id{};
    uint16_t transport_proto{};

    int64_t active_timeout{};
    int64_t idle_timeout{};

    Flow<TransportProto> src_to_dst;
    Flow<TransportProto> dst_to_src;
    Flow<TransportProto> bidirectional;
};

}

#endif
