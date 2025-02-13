#include <string>
#include <utility>
#include <tuple>
#include <nlohmann/json.hpp>
#include "dispatcher_ptr.h"
#include "util_plugins.h"
#include "default_keygen.h"

extern "C" void P_hex2dec(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    std::stringstream ss;
    ss << std::hex << record[field].get<std::string>();
    unsigned int x;
    ss >> x;
    record[field] = std::to_string(x);
}

extern "C" void P_plus(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    std::stringstream ss;
    ss << record[field].get<std::string>();
    unsigned int x;
    ss >> x;
    x += std::stoi(option);
    
    record[field] = std::to_string(x);
}

extern "C" void P_cal_no_angles(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    std::string nc = record["wlan.vht.mimo_control.nc"].get<std::string>();
    std::string nr = record["wlan.vht.mimo_control.nr"].get<std::string>();
    std::string nr_nc = nr +"_" + nc;

    if (nr_nc == "2_1" || nr_nc == "2_2")
        record[field] = "2";
    else if (nr_nc == "3_1")
        record[field] = "4";
    else if (nr_nc == "3_2" || nr_nc == "3_3" || nr_nc == "4_1")
        record[field] = "6";
    else if (nr_nc == "4_2")
        record[field] = "10";
    else if (nr_nc == "4_3" || nr_nc == "4_4")
        record[field] = "12";
}

extern "C" void P_comma2semicol(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    std::string no_angles = record[option].get<std::string>();

    std::stringstream ss;
    unsigned int x;
    ss << no_angles;
    ss >> x;

    std:: string original = record[field].get<std::string>();
    size_t pos = original.find(",", 0);
    size_t occurence = 0;
    while (pos != std::string::npos) {
        occurence++;
        if (occurence == x) {
            original[pos] = ';';
            occurence = 0;
        }
        pos = original.find(",", pos+1);
    }

    record[field] = original;
}