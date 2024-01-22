#ifndef FLOWMETER_SERVICEH
#define FLOWMETER_SERVICEH

#include "fmt/core.h"
#include "tins/constants.h"
#include "tins/dot1q.h"
#include "tins/ethernetII.h"
#include "tins/hw_address.h"
#include "tins/ip.h"
#include "tins/ipv6.h"
#include "tins/packet.h"
#include "tins/tcp.h"
#include "tins/udp.h"
#include <array>
#include <sstream>

#include "flowmeter/tins_ext.h"

namespace Net {

struct Service {
    MacAddress mac_addr;
    IpAddress ip_addr;
    uint16_t port;

    Service(MacAddress mac_address, IpAddress ip_address, uint16_t port_num)
        : mac_addr(mac_address), ip_addr(ip_address), port(port_num) {}

    Service() = default;

    bool operator>(const Service &service) const {
        if (port > service.port) {
            return true;
        } else if (port < service.port) {
            return false;
        }

        if (ip_addr > service.ip_addr) {
            return true;
        } else if (ip_addr < service.ip_addr) {
            return false;
        }

        if (mac_addr > service.mac_addr) {
            return true;
        } else if (mac_addr < service.mac_addr) {
            return false;
        }

        return false;
    }

    bool operator<=(const Service &service) const { return !operator>(service); }

    bool operator<(const Service &service) const {
        if (port < service.port) {
            return true;
        } else if (port > service.port) {
            return false;
        }

        if (ip_addr < service.ip_addr) {
            return true;
        } else if (ip_addr > service.ip_addr) {
            return false;
        }

        if (mac_addr < service.mac_addr) {
            return true;
        } else if (mac_addr > service.mac_addr) {
            return false;
        }

        return false;
    }

    bool operator>=(const Service &service) const { return !operator<(service); }

    bool operator==(const Service &service) const {
        return mac_addr == service.mac_addr && ip_addr == service.ip_addr &&
               port == service.port;
    }

    bool operator!=(const Service &service) const {
        return mac_addr != service.mac_addr || ip_addr != service.ip_addr ||
               port != service.port;
    }

    Service &operator=(const Service &service) {
        if (this == &service) {
            return *this;
        }

        this->mac_addr = service.mac_addr;
        this->ip_addr = service.ip_addr;
        this->port = service.port;

        return *this;
    }

    template <typename H>
    friend H AbslHashValue(H h, const Service &service) {
        return H::combine(std::move(h), service.mac_addr, service.ip_addr, service.port);
    }
};

class ServicePair {
  public:
    Service src_service{};
    Service dst_service{};
    Service l_service{src_service};
    Service r_service{dst_service};
    uint8_t vlan_id{0};
    Tins::Constants::IP::e transport_proto{};

    ServicePair(Tins::Packet &pkt) {
        if (eth_pdu_ptr_ = pkt.pdu()->find_pdu<Tins::EthernetII>()) {
            src_mac_ = eth_pdu_ptr_->src_addr();
            dst_mac_ = eth_pdu_ptr_->dst_addr();

            if (ipv6_pdu_ptr_ = eth_pdu_ptr_->find_pdu<Tins::IPv6>()) {
                to_bytes(ipv6_pdu_ptr_->src_addr(), src_addr_);
                to_bytes(ipv6_pdu_ptr_->dst_addr(), dst_addr_);
                // ip_version_ = Tins::Constants::Ethernet::e::IP;
                ip_version_ = 4;
            } else if (ip_pdu_ptr_ = eth_pdu_ptr_->find_pdu<Tins::IP>()) {
                to_bytes(ip_pdu_ptr_->src_addr(), src_addr_);
                to_bytes(ip_pdu_ptr_->dst_addr(), dst_addr_);
                // ip_version_ = Tins::Constants::Ethernet::e::IPV6;
                ip_version_ = 6;
            } else {
                return;
            }

            if (tcp_pdu_ptr_ = eth_pdu_ptr_->find_pdu<Tins::TCP>()) {
                src_port_ = tcp_pdu_ptr_->sport();
                dst_port_ = tcp_pdu_ptr_->dport();
                transport_proto = Tins::Constants::IP::e::PROTO_TCP;
            } else if (udp_pdu_ptr_ = eth_pdu_ptr_->find_pdu<Tins::UDP>()) {
                src_port_ = udp_pdu_ptr_->sport();
                dst_port_ = udp_pdu_ptr_->dport();
                transport_proto = Tins::Constants::IP::e::PROTO_UDP;
            } else {
                return;
            }

            src_service = {src_mac_, src_addr_, src_port_};
            dst_service = {dst_mac_, dst_addr_, dst_port_};

            l_service = src_service < dst_service ? src_service : dst_service;
            r_service = dst_service < src_service ? dst_service : src_service;

            if (dot1q_pdu_ptr_ = eth_pdu_ptr_->find_pdu<Tins::Dot1Q>()) {
                vlan_id = dot1q_pdu_ptr_->id();
            }
        }
    }

    ServicePair(Service &source, Service &dest, uint8_t vlan,
                Tins::Constants::IP::e transport)
        : src_service(source), dst_service(dest), l_service(src_service),
          r_service(dst_service), vlan_id(vlan), transport_proto(transport) {}

    ServicePair() = default;
    ServicePair(const ServicePair &pair) = default;

    const Tins::Constants::IP::e transport_protocol() const { return transport_proto; }

    template <typename H>
    friend H AbslHashValue(H h, const ServicePair &pair) {
        return H::combine(std::move(h), pair.l_service, pair.r_service, pair.vlan_id,
                          pair.transport_proto);
    }

    operator bool() const {
        return eth_pdu_ptr_ && (ip_pdu_ptr_ || ipv6_pdu_ptr_) &&
               (tcp_pdu_ptr_ || udp_pdu_ptr_);
    }

    bool operator==(const ServicePair &pair) const {
        return (transport_proto == pair.transport_proto) &&
               (l_service == pair.l_service) && (r_service == pair.r_service) &&
               (vlan_id == vlan_id);
    }

    bool operator!=(const ServicePair &pair) const { return !(*this) == pair; }

    const std::string column_names() const {
        return "src_mac,dst_mac,src_ip,dst_ip,sport,dport,vlan_id,ip_version";
    }

    const std::string to_string() const {
        std::stringstream ss;
        ss << eth_pdu_ptr_->src_addr().to_string() << ","
           << eth_pdu_ptr_->dst_addr().to_string() << ",";
        if (ip_pdu_ptr_) {
            ss << ip_pdu_ptr_->src_addr().to_string() << ","
               << ip_pdu_ptr_->dst_addr().to_string() << ",";
        } else {
            ss << ipv6_pdu_ptr_->src_addr().to_string() << ","
               << ipv6_pdu_ptr_->dst_addr().to_string() << ",";
        }
        if (tcp_pdu_ptr_) {
            ss << tcp_pdu_ptr_->sport() << "," << tcp_pdu_ptr_->dport() << ",";
        } else {
            ss << udp_pdu_ptr_->sport() << "," << udp_pdu_ptr_->dport() << ",";
        }
        ss << fmt::format("{}", vlan_id) << "," << fmt::format("{}", ip_version_);
        return ss.str();
    }

  private:
    MacAddress src_mac_;
    MacAddress dst_mac_;
    Tins::EthernetII *eth_pdu_ptr_{nullptr};
    Tins::TCP *tcp_pdu_ptr_{nullptr};
    Tins::UDP *udp_pdu_ptr_{nullptr};
    Tins::IPv6 *ipv6_pdu_ptr_{nullptr};
    Tins::IP *ip_pdu_ptr_{nullptr};
    IpAddress src_addr_{};
    IpAddress dst_addr_{};
    uint16_t src_port_;
    uint16_t dst_port_;
    uint8_t ip_version_;
    Tins::Dot1Q *dot1q_pdu_ptr_{nullptr};
};

} // end namespace Net

#endif
