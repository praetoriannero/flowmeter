#ifndef FLOWMETER_STATISTIC_H
#define FLOWMETER_STATISTIC_H

#include <sstream>
#include <string>

#include "flowmeter/constants.h"

namespace Net {

template <typename T>
struct Statistic {
    std::string name;
    T min;
    T max;
    T count;
    double mean;
    double stddev = 0;

    Statistic(std::string &stat_name, T &init_val)
        : name(stat_name), min(init_val), max(init_val), mean(init_val),
          count(1) {}

    void update(T &val) {
        count++;
        min = val < min ? val : min;
        max = val > max ? val : max;
        auto tmp_mean = mean;
        mean += (val - tmp_mean) / count;
        stddev += (val - tmp_mean) * (val - mean);
    }

    std::string header() {
        std::stringstream ss;
        ss << "min_" << name << ","
           << "max_" << name << ","
           << "mean_" << name << ","
           << "stddev_" << name << ",";
        return ss.str();
    }

    std::string to_string() {
        std::stringstream ss;
        ss << min << ","
           << max << ","
           << std::setprecision(MAX_DOUBLE_PRECISION) << mean << ","
           << std::setprecision(MAX_DOUBLE_PRECISION) << stddev;
        return ss.str();
    }
};

} // end namespace Net

#endif
