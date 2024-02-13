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
    std::string mac_addr;
    std::string ip_addr;
    uint16_t port;

    Service(std::string mac_address, std::string ip_address, uint16_t port_num)
        : mac_addr(mac_address), ip_addr(ip_address), port(port_num) {}

    Service(Service &rhs)
        : mac_addr(rhs.mac_addr), ip_addr(rhs.ip_addr), port(rhs.port) {}

    Service(const Service &rhs)
        : mac_addr(rhs.mac_addr), ip_addr(rhs.ip_addr), port(rhs.port) {}

    Service() = default;

    const std::string to_string() const {
        std::stringstream ss;
        ss << mac_addr << "," << ip_addr << "," << port;
        return ss.str();
    }

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
        return (mac_addr == service.mac_addr) && (ip_addr == service.ip_addr) &&
               (port == service.port);
    }

    bool operator!=(const Service &service) const {
        return (mac_addr != service.mac_addr) || (ip_addr != service.ip_addr) ||
               (port != service.port);
    }

    // Service operator=(const Service &service) {
    //     if (this == &service) {
    //         return *this;
    //     }

    //     this->mac_addr = service.mac_addr;
    //     this->ip_addr = service.ip_addr;
    //     this->port = service.port;

    //     return *this;
    // }

    // Service operator=(Service &service) {
    //     if (this == &service) {
    //         return *this;
    //     }

    //     this->mac_addr = service.mac_addr;
    //     this->ip_addr = service.ip_addr;
    //     this->port = service.port;

    //     return *this;
    // }

    template <typename H>
    friend H AbslHashValue(H h, const Service &service) {
        return H::combine(std::move(h), service.mac_addr, service.ip_addr, service.port);
    }
};

class ServicePair {
  public:
    std::string src_mac;
    std::string dst_mac;
    std::string src_addr;
    std::string dst_addr;
    uint8_t ip_version;
    Service src_service;
    Service dst_service;
    Service l_service;
    Service r_service;
    uint8_t vlan_id{0};
    uint16_t src_port;
    uint16_t dst_port;
    Tins::Constants::IP::e transport_proto{};
    static constexpr uint8_t IPv4 = 4;
    static constexpr uint8_t IPv6 = 6;

    ServicePair(Tins::Packet &pkt) {
        if (eth_pdu_ptr_ = pkt.pdu()->find_pdu<Tins::EthernetII>()) {
            src_mac = eth_pdu_ptr_->src_addr().to_string();
            dst_mac = eth_pdu_ptr_->dst_addr().to_string();

            if (ipv6_pdu_ptr_ = eth_pdu_ptr_->find_pdu<Tins::IPv6>()) {
                src_addr = ipv6_pdu_ptr_->src_addr().to_string();
                dst_addr = ipv6_pdu_ptr_->dst_addr().to_string();
                ip_version = IPv6;
            } else if (ip_pdu_ptr_ = eth_pdu_ptr_->find_pdu<Tins::IP>()) {
                src_addr = ip_pdu_ptr_->src_addr().to_string();
                dst_addr = ip_pdu_ptr_->dst_addr().to_string();
                ip_version = IPv4;
            } else {
                initialized_ = false;
                return;
            }

            if (tcp_pdu_ptr_ = eth_pdu_ptr_->find_pdu<Tins::TCP>()) {
                src_port = tcp_pdu_ptr_->sport();
                dst_port = tcp_pdu_ptr_->dport();
                transport_proto = Tins::Constants::IP::e::PROTO_TCP;
            } else if (udp_pdu_ptr_ = eth_pdu_ptr_->find_pdu<Tins::UDP>()) {
                src_port = udp_pdu_ptr_->sport();
                dst_port = udp_pdu_ptr_->dport();
                transport_proto = Tins::Constants::IP::e::PROTO_UDP;
            } else {
                initialized_ = false;
                return;
            }

            src_service = Service(src_mac, src_addr, src_port);
            dst_service = Service(dst_mac, dst_addr, dst_port);

            l_service = src_service < dst_service ? src_service : dst_service;
            r_service = dst_service < src_service ? dst_service : src_service;

            initialized_ = true;

            if (dot1q_pdu_ptr_ = eth_pdu_ptr_->find_pdu<Tins::Dot1Q>()) {
                vlan_id = dot1q_pdu_ptr_->id();
            }
        } else {
            initialized_ = false;
        }
    }

    ServicePair(Service &source, Service &dest, uint8_t vlan,
                Tins::Constants::IP::e transport)
        : src_service(source), dst_service(dest), l_service(l_service),
          r_service(r_service), vlan_id(vlan), transport_proto(transport) {}

    ServicePair(const ServicePair &pair)
        : src_service(pair.src_service), dst_service(pair.dst_service), l_service(pair.l_service),
          r_service(pair.r_service), vlan_id(pair.vlan_id), transport_proto(pair.transport_proto) {}

    ServicePair(ServicePair &pair)
        : src_service(pair.src_service), dst_service(pair.dst_service), l_service(pair.l_service),
          r_service(pair.r_service), vlan_id(pair.vlan_id), transport_proto(pair.transport_proto) {}

    void reset() {
        eth_pdu_ptr_ = nullptr;
        tcp_pdu_ptr_ = nullptr;
        udp_pdu_ptr_ = nullptr;
        ipv6_pdu_ptr_ = nullptr;
        ip_pdu_ptr_ = nullptr;
        dot1q_pdu_ptr_ = nullptr;
        initialized_ = false;
    }

    const Tins::Constants::IP::e transport_protocol() const { return transport_proto; }

    template <typename H>
    friend H AbslHashValue(H h, const ServicePair &pair) {
        return H::combine(std::move(h), pair.l_service, pair.r_service, pair.vlan_id,
                          pair.transport_proto);
    }

    operator bool() const {
        return initialized_;
    }

    const bool valid() const {
        return initialized_;
    } 

    bool operator==(const ServicePair &pair) const {
        return (transport_proto == pair.transport_proto) &&
               (l_service == pair.l_service) && (r_service == pair.r_service) &&
               (vlan_id == vlan_id);
    }

    bool operator!=(const ServicePair &pair) const { return !((*this) == pair); }

    const std::string column_names() const {
        return "src_mac,dst_mac,src_ip,dst_ip,sport,dport,vlan_id,ip_version";
    }

    const std::string to_string() const {
        std::stringstream ss;
        ss << src_service.mac_addr << "," << dst_service.mac_addr << ","
           << src_service.ip_addr << "," << dst_service.ip_addr << ","
           << src_service.port << "," << dst_service.port << "," << fmt::format("{}", vlan_id) << ","
           << fmt::format("{}", ip_version);
        return ss.str();
    }

  private:
    Tins::EthernetII *eth_pdu_ptr_{nullptr};
    Tins::TCP *tcp_pdu_ptr_{nullptr};
    Tins::UDP *udp_pdu_ptr_{nullptr};
    Tins::IPv6 *ipv6_pdu_ptr_{nullptr};
    Tins::IP *ip_pdu_ptr_{nullptr};
    Tins::Dot1Q *dot1q_pdu_ptr_{nullptr};
    bool initialized_{false};
};

} // end namespace Net

#endif
