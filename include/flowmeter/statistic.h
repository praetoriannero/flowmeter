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
    std::string header;
    T min = std::numeric_limits<T>::max();
    T max = std::numeric_limits<T>::min();
    T count = 0;
    double mean = 0;
    double stddev = 0;

    Statistic(std::string header_name, std::string stat_name)
        : header(header_name), name(stat_name) {}

    inline void update(T &val) {
        count++;
        min = val < min ? val : min;
        max = val > max ? val : max;
        double tmp_mean = mean;
        mean += (val - tmp_mean) / count;
        stddev += (val - tmp_mean) * (val - mean);
    }

    const std::string column_names() const {
        std::stringstream ss;
        ss << header << "_min_" << name << "," << header << "_max_" << name << ","
           << header << "_mean_" << name << "," << header << "_stddev_" << name;
        return ss.str();
    }

    const std::string to_string() const {
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
