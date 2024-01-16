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

#include "flowmeter/service.h"
#include "flowmeter/statistic.h"
#include "flowmeter/utils.h"

namespace Net {

enum ExpirationCode { UNINITIALIZED, ALIVE, ACTIVE_TIMEOUT, IDLE_TIMEOUT, USER_SPECIFIED };

struct FlowKey {
    Service l_service;  // "left" service, less than r_service
    Service r_service;  // "right" service, greather than l_service
    uint8_t vlan_id;
    uint8_t transport_proto;

    FlowKey(ServicePair &pair, const uint8_t vlan, const uint8_t protocol)
    : l_service(pair.l_service()),
      r_service(pair.r_service()),
      vlan_id(vlan),
      transport_proto(protocol) {}

    template <typename H>
    friend H AbslHashValue(H h, const FlowKey &key) {
        return H::combine(std::move(h), key.l_service, key.r_service, key.vlan_id, key.transport_proto);
    }

    bool operator==(const FlowKey &key) {
        return l_service == key.l_service &&
            r_service == key.r_service &&
            vlan_id == key.vlan_id &&
            transport_proto == key.transport_proto;
    }

    bool operator!=(const FlowKey &key) {
        return !(operator==(key));
    }
};

struct Flow {
    const Tins::Constants::IP::e transport_proto;
    std::string direction;
    double first_seen_ms = 0;
    double last_seen_ms = 0;
    double duration_ms = 0;
    uint64_t pkt_count = 0;
    uint64_t byte_count = 0;
    Statistic<uint64_t> packet_size{"ps"};   // packet size
    Statistic<double> packet_iat{"piat"};    // packet inter-arrival time
    uint64_t syn_count = 0;
    uint64_t cwr_count = 0;
    uint64_t ece_count = 0;
    uint64_t urg_count = 0;
    uint64_t ack_count = 0;
    uint64_t psh_count = 0;
    uint64_t rst_count = 0;
    uint64_t fin_count = 0;

    Flow(const std::string flow_direction, const Tins::Constants::IP::e transport_protocol)
    : direction(flow_direction),
      transport_proto(transport_protocol) {}

    void update(const Tins::Packet &packet) {
        auto pkt_timestamp = get_packet_timestamp(packet);
        pkt_count++;

        first_seen_ms = pkt_timestamp < first_seen_ms ? pkt_timestamp : first_seen_ms;
        auto tmp_last_seen_ms = last_seen_ms;
        last_seen_ms = pkt_timestamp > last_seen_ms ? pkt_timestamp : last_seen_ms;

        byte_count += packet.pdu()->size();;

        packet_size.update(byte_count);

        if (pkt_count > 1) {
            auto time_delta = last_seen_ms - tmp_last_seen_ms;
            packet_iat.update(time_delta);
        }

        if (transport_proto == Tins::Constants::IP::e::PROTO_TCP) {
            auto* tcp_pdu = packet.pdu()->find_pdu<Tins::TCP>();
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

    void finalize() {
        duration_ms = last_seen_ms - first_seen_ms;
    }

    std::string to_string() const {
        return "NOT IMPLEMENTED";
    }
};

struct NetworkFlow {
    ServicePair service_pair{};

    int64_t init_id{};
    int64_t sub_init_id{};

    ExpirationCode exp_code{ExpirationCode::UNINITIALIZED};

    std::string src_mac{};
    std::string dst_mac{};

    std::string src_ip{};
    std::string dst_ip{};

    uint16_t ip_version{};

    uint16_t src_port{};
    uint16_t dst_port{};

    uint16_t vlan_id{};
    Tins::Constants::IP::e transport_proto{};

    Flow src_to_dst;
    Flow dst_to_src;
    Flow bidirectional;

    NetworkFlow(const ServicePair& pair)
        : service_pair(pair),
          src_to_dst("src_to_dst", service_pair.transport_protocol()),
          dst_to_src("dst_to_src", service_pair.transport_protocol()),
          bidirectional("bidirectional", service_pair.transport_protocol()) {}

    void update(Tins::Packet &pkt, ServicePair &pair) {
        bidirectional.update(pkt);

        if (pair.src_service() == service_pair.src_service()) {
            src_to_dst.update(pkt);
        } else {
            dst_to_src.update(pkt);
        }
    }
};

} // end namespace Net

#endif
