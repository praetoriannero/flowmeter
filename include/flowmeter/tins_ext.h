#ifndef FLOWMETER_TINS_EXT_H
#define FLOWMETER_TINS_EXT_H

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>
#include "tins/ip_address.h"
#include "tins/ipv6_address.h"

namespace Net {

#define ADDR_SIZE 16

typedef std::array<uint8_t, ADDR_SIZE> IpAddress;
typedef Tins::HWAddress<6> MacAddress;

IpAddress to_bytes(Tins::IPv4Address addr) {
    IpAddress res_array;
    auto int_addr = uint32_t(addr);
    std::memcpy(res_array.data(), &int_addr, addr.size());
    return res_array;
}

IpAddress to_bytes(Tins::IPv6Address addr) {
    IpAddress res_array;
    auto i = 0;
    for (auto byte : addr) {
        res_array[i] = static_cast<uint8_t>(byte);
        i++;
    }
    return res_array;
}

} // end namespace Net

#endif
