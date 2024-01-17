#ifndef FLOWMETER_TINS_EXT_H
#define FLOWMETER_TINS_EXT_H

#include "tins/ip_address.h"
#include "tins/ipv6_address.h"
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

namespace Net {

#define ADDR_SIZE 16

typedef std::array<uint8_t, ADDR_SIZE> IpAddress;
typedef Tins::HWAddress<6> MacAddress;

void to_bytes(Tins::IPv4Address addr, IpAddress &addr_arr) {
    auto int_addr = uint32_t(addr);
    std::memcpy(addr_arr.data(), &int_addr, 4);
}

void to_bytes(Tins::IPv6Address addr, IpAddress &addr_arr) {
    auto i = 0;
    for (auto byte : addr) {
        addr_arr[i] = static_cast<uint8_t>(byte);
        i++;
    }
}

} // end namespace Net

#endif
