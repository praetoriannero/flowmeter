#ifndef FLOWMETER_SERVICE_H
#define FLOWMETER_SERVICE_H

#include <array>
#include "tins/ethernetII.h"
#include "tins/hw_address.h"
#include "tins/ip.h"
#include "tins/ipv6.h"
#include "tins/packet.h"
#include "tins/tcp.h"
#include "tins/udp.h"

#include "flowmeter/tins_ext.h"

namespace Net {

struct Service {
    MacAddress mac_addr;
    IpAddress ip_addr;
    uint16_t port;

    Service(MacAddress mac_address, IpAddress ip_address, uint16_t port_num)
    : mac_addr(mac_address),
      ip_addr(ip_address),
      port(port_num) {}

    Service(const Service &service)
    : mac_addr(service.mac_addr),
      ip_addr(service.ip_addr),
      port(service.port) {}

    Service() = default;

    bool operator>(const Service& service) const {
        if (mac_addr > service.mac_addr) {
            return true;
        } else if (mac_addr < service.mac_addr) {
            return false;
        }

        if (ip_addr > service.ip_addr) {
            return true;
        } else if (ip_addr < service.ip_addr) {
            return false;
        }
        
        if (port > service.port) {
            return true;
        } else if (port < service.port) {
            return false;
        }

        return false;
    }

    bool operator<=(const Service& service) const {
        return !operator>(service);
    }

    bool operator<(const Service& service) const {
        if (mac_addr < service.mac_addr) {
            return true;
        } else if (mac_addr > service.mac_addr) {
            return false;
        }

        if (ip_addr < service.ip_addr) {
            return true;
        } else if (ip_addr > service.ip_addr) {
            return false;
        }
        
        if (port < service.port) {
            return true;
        } else if (port > service.port) {
            return false;
        }

        return false;
    }

    bool operator>=(const Service& service) const {
        return !operator<(service);
    }

    bool operator==(const Service& service) const {
        return mac_addr == service.mac_addr &&
            ip_addr == service.ip_addr &&
            port == service.port;
    }

    bool operator!=(const Service& service) const {
        return mac_addr != service.mac_addr ||
            ip_addr != service.ip_addr ||
            port != service.port;
    }
};
//
class ServicePair {
  public:
    ServicePair(const Tins::Packet &pkt, const Tins::EthernetII *eth_pdu) {
        src_mac_ = eth_pdu->src_addr();
        dst_mac_ = eth_pdu->dst_addr();

        if (ipv6_pdu_ = eth_pdu->find_pdu<Tins::IPv6>()) {
            src_addr_ = to_bytes(ipv6_pdu_->src_addr());
            dst_addr_ = to_bytes(ipv6_pdu_->dst_addr());
        } else if (ip_pdu_ = eth_pdu->find_pdu<Tins::IP>()) {
            src_addr_ = to_bytes(ip_pdu_->src_addr());
            dst_addr_ = to_bytes(ip_pdu_->dst_addr());
        }

        if (tcp_pdu_ = eth_pdu->find_pdu<Tins::TCP>()) {
            src_port_ = tcp_pdu_->sport();
            dst_port_ = tcp_pdu_->dport();
        } else if (udp_pdu_ = eth_pdu->find_pdu<Tins::UDP>()) {
            src_port_ = udp_pdu_->sport();
            dst_port_ = udp_pdu_->dport();
        }

        src_service_ = {src_mac_, src_addr_, src_port_};
        dst_service_ = {dst_mac_, dst_addr_, dst_port_};
    }

    Service l_service() {
        return src_service_ < dst_service_ ? src_service_ : dst_service_;
    }

    Service r_service() {
        return dst_service_ < src_service_ ? dst_service_ : src_service_;
    }

  private:
    Service src_service_;
    Service dst_service_;
    MacAddress src_mac_;
    MacAddress dst_mac_;
    const Tins::EthernetII* eth_pdu_;
    const Tins::TCP* tcp_pdu_;
    const Tins::UDP* udp_pdu_;
    const Tins::IPv6* ipv6_pdu_;
    const Tins::IP* ip_pdu_;
    IpAddress src_addr_;
    IpAddress dst_addr_;
    uint16_t src_port_;
    uint16_t dst_port_;
};

} // end namespace Net

#endif
