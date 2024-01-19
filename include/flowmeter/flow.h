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
#include <limits>
#include <sstream>
#include <string_view>

#include "flowmeter/service.h"
#include "flowmeter/statistic.h"
#include "flowmeter/utils.h"

namespace Net {

enum ExpirationCode { UNINITIALIZED, ALIVE, ACTIVE_TIMEOUT, IDLE_TIMEOUT, USER_SPECIFIED };

struct Flow {
    const Tins::Constants::IP::e transport_proto{};
    std::string direction{"DEFAULT"};
    double first_seen_ms = std::numeric_limits<double>::max();
    double last_seen_ms = std::numeric_limits<double>::min();
    double duration_ms = 0;
    uint64_t pkt_count = 0;
    uint64_t byte_count = 0;
    Statistic<uint64_t> packet_size{direction, "ps"}; // packet size
    Statistic<double> packet_iat{direction, "piat"};  // packet inter-arrival time
    uint64_t syn_count = 0;
    uint64_t cwr_count = 0;
    uint64_t ece_count = 0;
    uint64_t urg_count = 0;
    uint64_t ack_count = 0;
    uint64_t psh_count = 0;
    uint64_t rst_count = 0;
    uint64_t fin_count = 0;

    Flow(const std::string direction_str, const Tins::Constants::IP::e transport_protocol)
        : direction(direction_str), transport_proto(transport_protocol) {}

    Flow(const Flow &flow) = default;

    inline void update(const Tins::Packet &packet, const double &pkt_timestamp) {
        if (!pkt_count) {
            first_seen_ms = pkt_timestamp;
        }

        pkt_count++;

        auto tmp_last_seen_ms = last_seen_ms;
        last_seen_ms = pkt_timestamp;

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

    const std::string to_string() const {
        std::stringstream ss;
        ss << std::setprecision(MAX_DOUBLE_PRECISION) << first_seen_ms << ","
           << std::setprecision(MAX_DOUBLE_PRECISION) << last_seen_ms << ","
           << std::setprecision(MAX_DOUBLE_PRECISION) << duration_ms << "," << pkt_count
           << "," << byte_count << "," << packet_size.to_string() << ","
           << packet_iat.to_string() << "," << syn_count << "," << cwr_count << ","
           << ece_count << "," << urg_count << "," << ack_count << "," << psh_count << ","
           << rst_count << "," << fin_count;
        return ss.str();
    }

    const std::string column_names() const {
        std::stringstream ss;
        ss << direction << "_first_seen_ms," << direction << "_last_seen_ms,"
           << direction << "_duration_ms," << direction << "_packet_count,"
           << direction << "_bytes," << packet_size.column_names() << ","
           << packet_iat.column_names() << "," << direction << "_syn_count," << direction << "_cwr_count,"
           << direction << "_ece_count," << direction << "_urg_count," << direction << "_ack_count," << direction << "_psh_count,"
           << direction << "_rst_count," << direction << "_fin_count";
        return ss.str();
    }
};

// struct Src2DstFlow : Flow {
//     std::string direction{"src2dst"};
//     using Flow::Flow;
// };

// struct Dst2SrcFlow : Flow {
//     std::string direction{"dst2src"};
//     using Flow::Flow;
// };

// struct BidirFlow : Flow {
//     std::string direction{"bidirectional"};
//     using Flow::Flow;
// };

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

    Flow src2dst;
    Flow dst2src;
    Flow bidirectional;

    NetworkFlow(const ServicePair &pair, const uint32_t init_id_val,
                const uint32_t sub_init_id_val)
        : service_pair(pair), init_id(init_id_val), sub_init_id(sub_init_id_val),
          src2dst("src2dst", pair.transport_proto), dst2src("dst2src", pair.transport_proto),
          bidirectional("bidirectional", pair.transport_proto), exp_code(ExpirationCode::ALIVE) {}

    NetworkFlow(const NetworkFlow &net_flow) = default;

    NetworkFlow operator=(const NetworkFlow rhs) { return rhs; };

    inline void update(Tins::Packet &pkt, ServicePair &pair, double &timestamp) {
        bidirectional.update(pkt, timestamp);

        if (pair.src_service == service_pair.src_service) {
            src2dst.update(pkt, timestamp);
        } else {
            dst2src.update(pkt, timestamp);
        }
    }

    double last_update_ts() const { return bidirectional.last_seen_ms; }

    const std::string column_names() const {
        std::stringstream ss;
        ss << "init_id,sub_init_id,expiration_reason," << bidirectional.column_names()
           << src2dst.column_names() << dst2src.column_names();
        return ss.str();
    }

    const std::string to_string() const {
        std::stringstream ss;
        ss << init_id << "," << sub_init_id << "," << exp_code << "," << bidirectional.to_string() << ","
           << src2dst.to_string() << "," << dst2src.to_string();
        return ss.str();
    }
};

} // end namespace Net

#endif
