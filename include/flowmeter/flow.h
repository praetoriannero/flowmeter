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
#include <bit>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <sstream>
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
    SESSION_END,
    USER_SPECIFIED
};

struct Flow {
    const Tins::Constants::IP::e transport_proto{};
    std::string direction{"DEFAULT"};
    double first_seen_ms = std::numeric_limits<double>::max();
    double last_seen_ms = std::numeric_limits<double>::min();
    double duration_ms = 0;
    uint64_t pkt_count = 0;
    uint64_t byte_count = 0;
    Statistic<uint64_t> packet_size{direction, "ps"};   // packet size
    Statistic<double> packet_iat{direction, "piat"};    // packet inter-arrival time
    Statistic<double> packet_entropy{direction, "ent"}; // packet entropy
    uint64_t null_byte_count = 0;
    uint64_t low_byte_count = 0;
    uint64_t char_byte_count = 0;
    uint64_t high_byte_count = 0;
    uint64_t syn_count = 0;
    uint64_t cwr_count = 0;
    uint64_t ece_count = 0;
    uint64_t urg_count = 0;
    uint64_t ack_count = 0;
    uint64_t psh_count = 0;
    uint64_t rst_count = 0;
    uint64_t fin_count = 0;

    inline void reset() {
        first_seen_ms = std::numeric_limits<double>::max();
        last_seen_ms = std::numeric_limits<double>::min();
        duration_ms = 0;
        pkt_count = 0;
        byte_count = 0;
        packet_size.reset();    // packet size
        packet_iat.reset();     // packet inter-arrival time
        packet_entropy.reset(); // packet entropy
        syn_count = 0;
        cwr_count = 0;
        ece_count = 0;
        urg_count = 0;
        ack_count = 0;
        psh_count = 0;
        rst_count = 0;
        fin_count = 0;
    }

    Flow(const std::string direction_str, const Tins::Constants::IP::e transport_protocol)
        : direction(direction_str), transport_proto(transport_protocol) {}

    Flow(const Flow &flow) = default;

    inline void update(Tins::Packet &packet, const double pkt_timestamp) {
        if (!pkt_count) {
            first_seen_ms = pkt_timestamp;
        }

        pkt_count++;

        auto total_bytes = packet.pdu()->size();

        uint32_t bit_count = 0;
        auto pkt_bytes = packet.pdu()->serialize();
        for (auto byte : pkt_bytes) {
            bit_count += std::popcount(byte);
        }
        double one_prob = static_cast<double>(bit_count) / (total_bytes * 8.0);
        double zero_prob = 1 - one_prob;
        double gini = 1.0 - ((one_prob * one_prob) + (zero_prob * zero_prob));
        packet_entropy.update(gini);

        byte_count += total_bytes;

        packet_size.update(total_bytes);

        if (pkt_count > 1) {
            packet_iat.update(pkt_timestamp - last_seen_ms);
        }
        last_seen_ms = pkt_timestamp;
        duration_ms = last_seen_ms - first_seen_ms;

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
           << packet_iat.to_string() << "," << packet_entropy.to_string() << ","
           << syn_count << "," << cwr_count << "," << ece_count << "," << urg_count << ","
           << ack_count << "," << psh_count << "," << rst_count << "," << fin_count;
        return ss.str();
    }

    const std::string column_names() const {
        std::stringstream ss;
        ss << direction << "_first_seen_ms," << direction << "_last_seen_ms," << direction
           << "_duration_ms," << direction << "_packet_count," << direction << "_bytes,"
           << packet_size.column_names() << "," << packet_iat.column_names() << ","
           << packet_entropy.column_names() << "," << direction << "_syn_count,"
           << direction << "_cwr_count," << direction << "_ece_count," << direction
           << "_urg_count," << direction << "_ack_count," << direction << "_psh_count,"
           << direction << "_rst_count," << direction << "_fin_count";
        return ss.str();
    }
};

struct NetworkFlow {
    ServicePair service_pair;

    int64_t init_id{};
    int64_t sub_init_id{};

    ExpirationCode exp_code{ExpirationCode::UNINITIALIZED};

    Flow src2dst;
    Flow dst2src;
    Flow bidirectional;

    NetworkFlow(const ServicePair pair, const uint32_t init_id_val,
                const uint32_t sub_init_id_val)
        : service_pair(pair), init_id(init_id_val), sub_init_id(sub_init_id_val),
          src2dst("src2dst", pair.transport_proto),
          dst2src("dst2src", pair.transport_proto),
          bidirectional("bidirectional", pair.transport_proto),
          exp_code(ExpirationCode::ALIVE) {}

    inline void reset() {
        src2dst.reset();
        dst2src.reset();
        bidirectional.reset();
    }

    NetworkFlow(const NetworkFlow &net_flow) = default;

    // NetworkFlow operator=(const NetworkFlow rhs) { return rhs; };

    // NetworkFlow operator=(NetworkFlow rhs) { return rhs; };

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
        ss << "init_id,sub_init_id,expiration_reason," << service_pair.column_names()
           << "," << bidirectional.column_names() << "," << src2dst.column_names() << ","
           << dst2src.column_names();
        return ss.str();
    }

    const std::string to_string() const {
        std::stringstream ss;
        ss << init_id << "," << sub_init_id << "," << exp_code << ","
           << service_pair.to_string() << "," << bidirectional.to_string() << ","
           << src2dst.to_string() << "," << dst2src.to_string();
        return ss.str();
    }
};

} // end namespace Net

#endif
