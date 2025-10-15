#include <string>
#include <utility>
#include <tuple>
#include <limits>

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
    double result = 0.0f;
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


/**
 * @brief Child granularity's field aggregation, without skipping empty fields
 * 
 */
extern "C" void P_childstdev(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    // option contains out_pkt field name
    // idx contains flow idx
    double mean = 0.0f;

    std::vector<double> stat;
    std::string child_g = fpnt::d->g_lvs[fpnt::d->g_lv_idx[granularity] - 1];
    size_t count = 0;
    for(auto & child_key: fpnt::d->out_child_keys[granularity][key]) {
        nlohmann::json& cnt = fpnt::d->out[child_g][child_key];
        if (!cnt[option].is_null()) {
            std::string val_str = cnt[option].get<std::string>();
            double cur_value = atof(val_str.c_str());
            stat.push_back(cur_value);
            mean += cur_value;
            count++;
        }
    }
    
    if (count <= 1) { // undefined value
        record[field] = std::to_string(-1); 
        return;
    }
    
    // always count > 0
        mean /= count;

    double sampled_standard_deviation = 0.0f;
    for (auto & cur_value: stat) {
        double deviation = cur_value - mean;
        sampled_standard_deviation += deviation * deviation;
    }

    sampled_standard_deviation /= count - 1; // sampled!
    sampled_standard_deviation = sqrt(sampled_standard_deviation);
    
    record[field] = std::to_string(sampled_standard_deviation);
}

/**
 * @brief Child granularity's field max, assuming double
 * 
 */
extern "C" void P_childmax_d(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    // option contains out_pkt field name
    // idx contains flow idx
    double result = std::numeric_limits<double>::lowest();
    std::string child_g = fpnt::d->g_lvs[fpnt::d->g_lv_idx[granularity] - 1];
    for(auto & child_key: fpnt::d->out_child_keys[granularity][key]) {
        nlohmann::json& cnt = fpnt::d->out[child_g][child_key];
        if (!cnt[option].is_null()) {
            std::string val_str = cnt[option].get<std::string>();
            double cur_value = atof(val_str.c_str());
            if (cur_value > result)
                result = cur_value;
        }
    }
    record[field] = std::to_string(result);
}

/**
 * @brief Child granularity's field min, assuming double
 * 
 */
extern "C" void P_childmin_d(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    // option contains out_pkt field name
    // idx contains flow idx
    double result = std::numeric_limits<double>::max();
    std::string child_g = fpnt::d->g_lvs[fpnt::d->g_lv_idx[granularity] - 1];
    for(auto & child_key: fpnt::d->out_child_keys[granularity][key]) {
        nlohmann::json& cnt = fpnt::d->out[child_g][child_key];
        if (!cnt[option].is_null()) {
            std::string val_str = cnt[option].get<std::string>();
            double cur_value = atof(val_str.c_str());
            if (cur_value < result)
                result = cur_value;
        }
    }
    record[field] = std::to_string(result);
}

/**
 * @brief Child granularity's field max, assuming long long
 * 
 */
extern "C" void P_childmax_ll(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    // option contains out_pkt field name
    // idx contains flow idx
    long long result = std::numeric_limits<long long>::lowest();
    std::string child_g = fpnt::d->g_lvs[fpnt::d->g_lv_idx[granularity] - 1];
    for(auto & child_key: fpnt::d->out_child_keys[granularity][key]) {
        nlohmann::json& cnt = fpnt::d->out[child_g][child_key];
        if (!cnt[option].is_null()) {
            std::string val_str = cnt[option].get<std::string>();
            long long cur_value = atoll(val_str.c_str());
            if (cur_value > result)
                result = cur_value;
        }
    }
    record[field] = std::to_string(result);
}

/**
 * @brief Child granularity's field min, assuming long long
 * 
 */
extern "C" void P_childmin_ll(std::string& option, nlohmann::json& record, const std::string& granularity, const std::string& key, const std::string &field) {
    // option contains out_pkt field name
    // idx contains flow idx
    long long result = std::numeric_limits<long long>::max();
    std::string child_g = fpnt::d->g_lvs[fpnt::d->g_lv_idx[granularity] - 1];
    for(auto & child_key: fpnt::d->out_child_keys[granularity][key]) {
        nlohmann::json& cnt = fpnt::d->out[child_g][child_key];
        if (!cnt[option].is_null()) {
            std::string val_str = cnt[option].get<std::string>();
            long long cur_value = atoll(val_str.c_str());
            if (cur_value < result)
                result = cur_value;
        }
    }
    record[field] = std::to_string(result);
}