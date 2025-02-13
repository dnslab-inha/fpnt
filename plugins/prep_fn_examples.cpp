#include <string>
#include <utility>
#include <tuple>
#include <nlohmann/json.hpp>
#include "dispatcher_ptr.h"
#include "util_plugins.h"
#include "default_keygen.h"

extern "C" void P_debug(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    std::cout << "field (name): " << field << "\t";

    if (record[field].is_null()) {
          std::cout << "This field is currently null!" << std::endl;
          return;
    }

    std::cout << "field (value) : " << record[field].get<std::string>() << "\t";
    std::cout << "field (value; without get) : " << record[field] << "\t";
    std::cout << "Option: " << option << "\t";
    std::cout << "Out Record: " << record.dump() << "\t";
    std::cout << "Mapper: ";
    auto x = fpnt::d->in_map.getFields();
    for (int i = 0; i < x.size(); i++) {
        std::cout << x[i];
        if (i == x.size() - 1)
            std::cout << "\t";
        else
            std::cout << ", ";
    }
    std::cout << "In Packet Index (idx): " << std::to_string(record["__in_idx"].get<size_t>()) << std::endl;
    std::cout << "Out Index (idx): " << std::to_string(fpnt::d->out_key2idx[granularity][key]) << std::endl;
    std::cout << "Dispatcher pointer: " << fpnt:: d << std::endl;
    std::cout << "Dispatcher in_pkts size: " << fpnt::d->in_pkts.size() << std::endl;
    std::cout << "Accessing in_pkts using idx: " << fpnt::d->in_pkts[record["__in_idx"]].dump() << std::endl;
}

extern "C" void P_cpy(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
//    auto x = fpnt::d->in_map.getFields();
    
//    if (&map == &fpnt::d->map_pkt)
//    std::cout << "Out " << field << " Opt " << option << " ptr " << fpnt::d << " idx " << idx << " sz " << fpnt::d->in_pkts.size() << std::endl;
//    std::cout << fpnt::d->in_pkts[idx].dump() << std::endl;
//    std::cout << fpnt::d->in_pkts[idx][option] << std::endl;
//    std::cout << record.dump() << std::endl;
    const size_t idx = record["__in_idx"].get<size_t>();
    if(fpnt::d->in_pkts[idx][option].is_null())
        record[field] = "";
    else
        record[field] = fpnt::d->in_pkts[idx][option].get<std::string>();
}

extern "C" void P_move(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    const size_t idx = record["__in_idx"];
    record[field] = std::move(fpnt::d->in_pkts[idx][option]);
}


/**
 * @brief Child granularity's field aggregation, without skipping empty fields
 * 
 */
extern "C" void P_childagg(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    // option contains out_pkt field name
    // idx contains flow idx
    std::string result = "";
    bool first = true;
    std::string child_g = fpnt::d->g_lvs[fpnt::d->g_lv_idx[granularity] - 1];
    for(auto & child_key: fpnt::d->out_child_keys[granularity][key]) {
        if (first) {
            first = false;
        } else {
            result += ",";
        }
        nlohmann::json& cnt = fpnt::d->out[child_g][child_key];
        if (!cnt[option].is_null())
            result += cnt[option].get<std::string>();
    }
    record[field] = result;
}

/**
 * @brief Packet field aggregation for flow, with skipping empty fields
 * 
 */
extern "C" void P_skipchildagg(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    // option contains out_pkt field name
    // idx contains flow idx
    std::string result = "";
    bool first = true;
    std::string child_g = fpnt::d->g_lvs[fpnt::d->g_lv_idx[granularity] - 1];
    for(auto & child_key: fpnt::d->out_child_keys[granularity][key]) {
        nlohmann::json& cnt = fpnt::d->out[child_g][child_key];
        if (!cnt[option].is_null() && cnt[option] != "") {
            if (first) {
                first = false;
            } else {
                result += ",";
            }
            
                result += cnt[option].get<std::string>();
        }
    }
    record[field] = result;
}

/**
 * @brief Interarrival Time Sequence for Flow
 * 
 */
extern "C" void P_iat(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    // option contains out_pkt field name
    // idx contains flow idx
    std::string result = "";
    std::vector<double> arrival_times;

    for(auto& pkt_key: fpnt::get_keys(key, granularity,"pkt")) {
        nlohmann::json& cnt = fpnt::d->out["pkt"][pkt_key];
        if (cnt[option].is_null()) {
            std::cerr << "P_iat4flow: Empty arrival time value!" << std::endl;
            exit(1);
        }

        double cnt_arrival_time = stod(cnt[option].get<std::string>());
        arrival_times.push_back(cnt_arrival_time);

    }

    std::vector<double> iats;
    if (arrival_times.size() > 1) {
        for (size_t i = 1; i < arrival_times.size(); ++i) {
            iats.push_back(arrival_times[i] - arrival_times[i - 1]);
        }

        record[field] = vectorToString(iats);
    } else {
        record[field] = "";
    }
}

/**
 * @brief Return Child count
 * 
 */
extern "C" void P_childcount(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    record[field] = std::to_string(fpnt::d->out_child_keys[granularity][key].size());
}


/**
 * @brief Packet count for any granuality (without packet)
 * 
 */
extern "C" void P_pktcount(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    record[field] = std::to_string(fpnt::get_keys(key, granularity,"pkt").size());
}

/**
 * @brief Packet field aggregation for flowset, without skipping empty fields
 * 
 */
extern "C" void P_pf_agg(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    // option contains out_pkt field name
    // idx contains flow idx
    std::string result = "";
    bool first = true;
    for(auto & pkt_key: fpnt::get_keys(key, granularity,"pkt")) {
        if (first) {
            first = false;
        } else {
            result += ",";
        }
        if (!fpnt::d->out["pkt"][pkt_key][option].is_null())
            result += fpnt::d->out["pkt"][pkt_key][option].get<std::string>();
    }
    record[field] = result;
}

/**
 * @brief Packet field aggregation for flowset, with skipping empty fields
 * 
 */
extern "C" void P_skip_pf_agg(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    // option contains out_pkt field name
    // idx contains flow idx
    std::string result = "";
    bool first = true;
    for(auto & pkt_key: fpnt::get_keys(key, granularity,"pkt")) {
        nlohmann::json& cnt = fpnt::d->out["pkt"][pkt_key];
        if (!cnt[option].is_null() && cnt[option] != "") {
            if (first) {
                first = false;
            } else {
                result += ",";
            }
                result += cnt[option].get<std::string>();
        }
    }
    record[field] = result;
}

/** P_fill1: fill if empty
 * 
 */
extern "C" void P_fill1(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    const size_t idx = record["__in_idx"];
    if(record[field] == "")
      record[field] = fpnt::d->in_pkts[idx][option];
}

/** P_firstcpy4flow: copy the first child's value for flow (typically expecting that the packets in the flow have the same value)
 * 
 */
extern "C" void P_firstcpy(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    std::string child_g = fpnt::d->g_lvs[fpnt::d->g_lv_idx[granularity] - 1];
    auto & first_child_key = fpnt::d->out_child_keys[granularity][key][0];
    record[field] = fpnt::d->out[child_g][first_child_key][option];
}

/** P_fillOpt: fill with option value
 * 
 */
extern "C" void P_fillOpt(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    record[field] = option;
}

extern "C" void P_saveKey(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    record[field] = record["__" + option + "_key"];
}

extern "C" void P_saveFlowKey(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    record[field] = record["__flow_key"];
}

extern "C" void P_saveFlowsetKey(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    record[field] = record["__flowset_key"];
}

extern "C" void P_savePktKey(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    record[field] = record["__pkt_key"];
}
