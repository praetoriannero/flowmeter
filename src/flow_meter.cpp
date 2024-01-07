#include <chrono>
#include <iostream>
#include <string>
#include <stdexcept>
#include <map>
#include "tins/ip.h"
#include "tins/sniffer.h"
#include "tins/packet.h"
#include <fmt/core.h>

enum ExpirationCode { ALIVE, ACTIVE_TIMEOUT, IDLE_TIMEOUT, USER_SPECIFIED };

struct Feature {
    std::string name{};
    
};

struct Flow {
    Flow(int64_t active_timeout, int64_t idle_timeout)
    : active_timeout_(active_timeout),
      idle_timeout_(idle_timeout) {}

    void update(Tins::Packet& pkt) {
        auto tmp = pkt;
    }

    // void add_field(std::string field_name, )

    // auto flow_feature_count = 0;

    int64_t init_id_{};
    int64_t sub_init_id{};

    ExpirationCode exp_reason{};

    std::string src_mac_{};
    std::string dst_mac_{};

    std::string src_ip_{};
    std::string dst_ip_{};

    uint16_t ip_version_{};

    uint16_t src_port_{};
    uint16_t dst_port_{};

    uint16_t vlan_id_{};
    uint16_t transport_proto_{};

    int64_t active_timeout_{};
    int64_t idle_timeout_{};


};


class Reader {
public:
    Reader(const std::string& input_file)
    : sniffer_(input_file) {}

    void run() {
        Tins::Packet packet;
        auto start_time = std::chrono::high_resolution_clock::now();
        auto pkt_cnt = 0;
        while (packet = sniffer_.next_packet()) {
            pkt_cnt++;
        }
        auto end_time = std::chrono::high_resolution_clock::now();
        auto nanosecs = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();
        std::cout << nanosecs << std::endl;
        double seconds = nanosecs / 1'000'000'000.0;
        fmt::print("{}\n", seconds);
        double pkts_per_sec = pkt_cnt / seconds;
        std::cout << "Read " << pkt_cnt << " packets in " << seconds << " seconds" << std::endl;
        std::cout << pkts_per_sec << " pkts/sec" << std::endl;
    }
private:
    Tins::FileSniffer sniffer_;
};

int main(int argc, char* argv[]) {
    fmt::print("It worked!\n");
    if (argc != 2) {
        std::cout << "Usage: " << argv[0] << " <input-file>" << std::endl;
        return 1;
    }
    try {
        // Build the defragmented
        Reader reader(argv[1]);
        std::cout << "Processing " << argv[1] << std::endl;

        // Run!
        reader.run();
        std::cout << "Done" << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
    }
}
