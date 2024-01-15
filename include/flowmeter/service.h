#ifndef FLOWMETER_SERVICE_H
#define FLOWMETER_SERVICE_H

#include <array>
#include "tins/ethernetII.h"
#include "tins/hw_address.h"
#include "tins/ip.h"
#include "tins/ipv6.h"
#include "tins/tcp.h"
#include "tins/udp.h"

#include "flowmeter/tins_ext.h"

using MacAddress = Tins::HWAddress<6>;
using IpAddress = std::array<uint8_t, ADDR_SIZE>;

template <typename IpVersion>
struct Service {
    MacAddress mac_addr;
    IpAddress ip_addr;
    uint16_t port;

    Service(MacAddress mac_address, IpAddress ip_address, uint16_t port_num)
    : mac_addr(mac_address),
      ip_addr(ip_address),
      port(port_num) {}

    bool operator>(const Service& service) {
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

    bool operator<=(const Service& service) {
        return !operator>(service);
    }

    bool operator<(const Service& service) {
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

    bool operator>=(const Service& service) {
        return !operator<(service);
    }

    bool operator==(const Service& service) {
        return mac_addr == service.mac_addr &&
            ip_addr == service.ip_addr &&
            port == service.port;
    }

    bool operator!=(const Service& service) {
        return mac_addr != service.mac_addr ||
            ip_addr != service.ip_addr ||
            port != service.port;
    }
};

template <typename IpVersion>
class ServicePair {
  public:
    Service<IpVersion> src_service;
    Service<IpVersion> dst_service;

    ServicePair(const Service<IpVersion> &source, const Service<IpVersion> &destination) 
    : src_service(source),
      dst_service(source) {}

    ServicePair(const Tins::Packet &pkt, const Tins::EthernetII &eth_pdu) {
        if 

        if (tcp_pdu_ = pkt.find_pdu<Tins::TCP>) {
            src_port_ = tcp_pdu_->sport();
            dst_port_ = tcp_pdu_->dport();
        } else if (udp_pdu_ = pkt.find_pdu<Tins::UDP) {
            src_port_ = udp_pdu_->sport();
            dst_port_ = udp_pdu_->dport();
        }
    }

    uint16_t sport() {
        return src_port_;
    }

    uint16_t dport() {
        return dst_port_;
    }

  private:
    Tins::EthernetII* eth_pdu_;
    Tins::TCP* tcp_pdu_;
    Tins::UDP* udp_pdu_;
    Tins::IPv6* ipv6_pdu_;
    Tins::IP* ip_pdu_;
    uint16_t src_port_;
    uint16_t dst_port_;
};

#endif
