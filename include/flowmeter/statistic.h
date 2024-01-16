#ifndef FLOWMETER_STATISTIC_H
#define FLOWMETER_STATISTIC_H

#include <limits>
#include <sstream>
#include <string>

#include "flowmeter/constants.h"

namespace Net {

template <typename T>
struct Statistic {
    std::string name;
    T min = std::numeric_limits<T>::max();
    T max = std::numeric_limits<T>::min();
    T count = 0;
    double mean = 0;
    double stddev = 0;

    Statistic(std::string stat_name) : name(stat_name) {}

    void update(T &val) {
        count++;
        min = val < min ? val : min;
        max = val > max ? val : max;
        double tmp_mean = mean;
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
        if constexpr (std::is_same<T, double>()) {
            ss << std::setprecision(MAX_DOUBLE_PRECISION) << min << ","
               << std::setprecision(MAX_DOUBLE_PRECISION) << max << ",";
        } else {
            ss << min << "," << max << ",";
        }
        ss << std::setprecision(MAX_DOUBLE_PRECISION) << mean << ","
           << std::setprecision(MAX_DOUBLE_PRECISION) << stddev;
        return ss.str();
    }
};

} // end namespace Net

#endif
