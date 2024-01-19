#ifndef FLOWMETER_FLOW_H
#define FLOWMETER_FLOW_H

#include "tins/hw_address.h"
#include "tins/ip.h"
#include "tins/ip_address.h"
#include "tins/ipv6.h"
#include "tins/ipv6_address.h"
#include "tins/packet.h"
#include "tins/tcp.h"
#include "tins/udp.h"
#include <cstdint>
#include <string_view>

#include "flowmeter/service.h"
#include "flowmeter/statistic.h"
#include "flowmeter/utils.h"

namespace Net {

enum ExpirationCode {
    UNINITIALIZED,
    ALIVE,
    ACTIVE_TIMEOUT,
    IDLE_TIMEOUT,
    USER_SPECIFIED
};

struct Flow {
    const Tins::Constants::IP::e transport_proto{};
    std::string direction{"DEFAULT"};
    double first_seen_ms = 0;
    double last_seen_ms = 0;
    double duration_ms = 0;
    uint64_t pkt_count = 0;
    uint64_t byte_count = 0;
    Statistic<uint64_t> packet_size{"ps"}; // packet size
    Statistic<double> packet_iat{"piat"};  // packet inter-arrival time
    uint64_t syn_count = 0;
    uint64_t cwr_count = 0;
    uint64_t ece_count = 0;
    uint64_t urg_count = 0;
    uint64_t ack_count = 0;
    uint64_t psh_count = 0;
    uint64_t rst_count = 0;
    uint64_t fin_count = 0;

    Flow(const Tins::Constants::IP::e transport_protocol)
        : transport_proto(transport_protocol) {}

    Flow(const Flow &flow) = default;

    inline void update(const Tins::Packet &packet, const double &pkt_timestamp) {
        pkt_count++;

        first_seen_ms =
            pkt_timestamp < first_seen_ms ? pkt_timestamp : first_seen_ms;
        auto tmp_last_seen_ms = last_seen_ms;
        last_seen_ms =
            pkt_timestamp > last_seen_ms ? pkt_timestamp : last_seen_ms;

        byte_count += packet.pdu()->size();

        packet_size.update(byte_count);

        if (pkt_count > 1) {
            auto time_delta = last_seen_ms - tmp_last_seen_ms;
            packet_iat.update(time_delta);
        }

        if (transport_proto == Tins::Constants::IP::e::PROTO_TCP) {
            auto *tcp_pdu = packet.pdu()->find_pdu<Tins::TCP>();

            if (tcp_pdu->get_flag(Tins::TCP::SYN)) {
                syn_count++;
            }
            if (tcp_pdu->get_flag(Tins::TCP::CWR)) {
                cwr_count++;
            }
            if (tcp_pdu->get_flag(Tins::TCP::ECE)) {
                ece_count++;
            }
            if (tcp_pdu->get_flag(Tins::TCP::URG)) {
                urg_count++;
            }
            if (tcp_pdu->get_flag(Tins::TCP::ACK)) {
                ack_count++;
            }
            if (tcp_pdu->get_flag(Tins::TCP::PSH)) {
                psh_count++;
            }
            if (tcp_pdu->get_flag(Tins::TCP::RST)) {
                rst_count++;
            }
            if (tcp_pdu->get_flag(Tins::TCP::FIN)) {
                fin_count++;
            }
        }
    }

    inline void finalize() { duration_ms = last_seen_ms - first_seen_ms; }

    std::string to_string() const { return "NOT IMPLEMENTED"; }
};

struct Src2DstFlow : Flow {
    std::string direction{"src_to_dst"};
    using Flow::Flow;
};

struct Dst2SrcFlow : Flow {
    std::string direction{"dst_to_src"};
    using Flow::Flow;
};

struct BidirFlow : Flow {
    std::string direction{"bidirectional"};
    using Flow::Flow;
};

struct NetworkFlow {
    ServicePair service_pair{};

    int64_t init_id{};
    int64_t sub_init_id{};

    ExpirationCode exp_code{ExpirationCode::UNINITIALIZED};

    // std::string src_mac{};
    // std::string dst_mac{};

    // std::string src_ip{};
    // std::string dst_ip{};

    // uint16_t ip_version{};

    // uint16_t src_port{};
    // uint16_t dst_port{};

    // uint16_t vlan_id{};
    // Tins::Constants::IP::e transport_proto{};

    Src2DstFlow src_to_dst;
    Dst2SrcFlow dst_to_src;
    BidirFlow bidirectional;

    NetworkFlow(const ServicePair &pair, const uint32_t init_id_val, const uint32_t sub_init_id_val)
        : service_pair(pair),
          init_id(init_id_val),
          sub_init_id(sub_init_id_val),
          src_to_dst(pair.transport_proto),
          dst_to_src(pair.transport_proto),
          bidirectional(pair.transport_proto),
          exp_code(ExpirationCode::ALIVE) {}

    NetworkFlow(const NetworkFlow &net_flow) = default;

    // NetworkFlow& operator=(NetworkFlow &rhs) {
    //     return rhs;
    // };
    NetworkFlow operator=(const NetworkFlow rhs) {
        return rhs;
    };

    inline void update(Tins::Packet &pkt, ServicePair &pair, double &timestamp) {
        bidirectional.update(pkt, timestamp);

        if (pair.src_service == service_pair.src_service) {
            src_to_dst.update(pkt, timestamp);
        } else {
            dst_to_src.update(pkt, timestamp);
        }
    }

    double last_update_ts() const { return bidirectional.last_seen_ms; }
};

} // end namespace Net

#endif
