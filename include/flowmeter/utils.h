#ifndef FLOWMETER_UTILS_H
#define FLOWMETER_UTILS_H

#include "tins/packet.h"

double get_packet_timestamp(const Tins::Packet& packet) {
    return static_cast<double>(packet.timestamp().seconds()) /
        static_cast<double>(packet.timestamp().microseconds());
}


#endif
