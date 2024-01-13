#ifndef FLOWMETER_NODE_H
#define FLOWMETER_NODE_H

#include <cstdint>

struct NetNode {
    // counts for incoming/outgoing ports
    uint64_t inc_port;
    uint64_t out_port;

    // pe = port entropy
    double inc_pe;
    double out_pe;

    uint64_t udp_count;
    uint64_t tcp_count;

    uint64_t ip_count;
    uint64_t ip6_count;

    uint64_t nontransport_count;

    uint64_t degree;

    uint64_t min_peer_degree;
    uint64_t max_peer_degree;
    double mean_peer_degree;
    double stddev_peer_degree;

    // bytes per second per peer connection
    // edge weights-ish
    uint64_t min_data_flow;
    uint64_t max_data_flow;
    double mean_data_rate;
    double stddev_data_rate;

    // num node pairs in neighborhood / total pairs
    double connectivity;
};

#endif
