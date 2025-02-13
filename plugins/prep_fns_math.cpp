#include <string>
#include <utility>
#include <tuple>
#include <nlohmann/json.hpp>
#include "dispatcher_ptr.h"
#include "util_plugins.h"
#include "default_keygen.h"


/**
 * @brief Child granularity's field sum, without skipping empty fields; assuming long long
 * 
 */
extern "C" void P_childsum_ll(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    // option contains out_pkt field name
    // idx contains flow idx
    long long result = 0;
    std::string child_g = fpnt::d->g_lvs[fpnt::d->g_lv_idx[granularity] - 1];
    for(auto & child_key: fpnt::d->out_child_keys[granularity][key]) {
        nlohmann::json& cnt = fpnt::d->out[child_g][child_key];
        if (!cnt[option].is_null()) {
            std::string val_str = cnt[option].get<std::string>();
            result += atoll(val_str.c_str());
        }
    }
    record[field] = std::to_string(result);
}


/**
 * @brief Child granularity's field sum, without skipping empty fields, assuming double
 * 
 */
extern "C" void P_childsum_d(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    // option contains out_pkt field name
    // idx contains flow idx
    double result = 0;
    std::string child_g = fpnt::d->g_lvs[fpnt::d->g_lv_idx[granularity] - 1];
    for(auto & child_key: fpnt::d->out_child_keys[granularity][key]) {
        nlohmann::json& cnt = fpnt::d->out[child_g][child_key];
        if (!cnt[option].is_null()) {
            std::string val_str = cnt[option].get<std::string>();
            result += atof(val_str.c_str());
        }
    }
    record[field] = std::to_string(result);
}



/**
 * @brief Child granularity's field aggregation, without skipping empty fields
 * 
 */
extern "C" void P_childmean(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    // option contains out_pkt field name
    // idx contains flow idx
    double result = 0;
    std::string child_g = fpnt::d->g_lvs[fpnt::d->g_lv_idx[granularity] - 1];
    size_t count = 0;
    for(auto & child_key: fpnt::d->out_child_keys[granularity][key]) {
        nlohmann::json& cnt = fpnt::d->out[child_g][child_key];
        if (!cnt[option].is_null()) {
            std::string val_str = cnt[option].get<std::string>();
            result += atof(val_str.c_str());
            count++;
        }
    }
    
    if (count>0)
        result /= count;

    record[field] = std::to_string(result);
}

