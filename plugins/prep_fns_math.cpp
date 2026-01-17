#include <limits>
#include <nlohmann/json.hpp>
#include <string>
#include <tuple>
#include <utility>

#include "default_keygen.h"
#include "dispatcher_ptr.h"
#include "util_plugins.h"

/**
 * @brief Same granularity's field max, assuming double
 *
 */
extern "C" void P_max_d(std::string& option, nlohmann::json& record, const std::string& granularity,
                        const std::string& key, const std::string& field) {
  nlohmann::json& cnt = fpnt::d->out[granularity][key];
  std::string vectorString = cnt[option];
  std::vector<double> values = stringToVector(vectorString);

  double result = std::numeric_limits<double>::lowest();
  for (const auto& val : values) {
    if (val > result) result = val;
  }

  if (result == std::numeric_limits<double>::lowest()) {
    // No valid values found
    record[field] = "";
  } else {
    record[field] = std::to_string(result);
  }
}

/**
 * @brief Same granularity's field min, assuming double
 *
 */
extern "C" void P_min_d(std::string& option, nlohmann::json& record, const std::string& granularity,
                        const std::string& key, const std::string& field) {
  nlohmann::json& cnt = fpnt::d->out[granularity][key];
  std::string vectorString = cnt[option];
  std::vector<double> values = stringToVector(vectorString);

  double result = std::numeric_limits<double>::max();
  for (const auto& val : values) {
    if (val < result) result = val;
  }

  if (result == std::numeric_limits<double>::max()) {
    // No valid values found
    record[field] = "";
  } else {
    record[field] = std::to_string(result);
  }
}

/**
 * @brief Child granularity's field sum, skipping empty fields; assuming long long
 *
 */
extern "C" void P_childsum_ll(std::string& option, nlohmann::json& record,
                              const std::string& granularity, const std::string& key,
                              const std::string& field) {
  // option contains out_pkt field name
  // however, postfix '+' or '-' can be possible (assuming that field name does not allow postfix
  // '+' or '-').
  std::string fieldname = option;
  bool check_dir, dir;

  // check fieldname is empty
  if (fieldname.empty()) {
    exit(1);
  }

  // fieldname's last character
  char lastChar = fieldname.back();

  if (lastChar == '+') {
    check_dir = true;
    dir = true;
    fieldname.pop_back();
  } else if (lastChar == '-') {
    check_dir = true;
    dir = false;
    fieldname.pop_back();
  } else {  // otherwise
    check_dir = false;
    dir = false;
  }

  // idx contains flow idx
  long long result = 0;
  std::string child_g = fpnt::d->g_lvs[fpnt::d->g_lv_idx[granularity] - 1];
  for (auto& child_key : fpnt::d->out_child_keys[granularity][key]) {
    nlohmann::json& cnt = fpnt::d->out[child_g][child_key];
    if (!cnt[fieldname].is_null()) {
      std::string val_str = cnt[fieldname].get<std::string>();
      long long temp = atoll(val_str.c_str());

      if (check_dir) {  // we should check direction
        long long dir_value = atoll(cnt["__dir"].get<std::string>().c_str());
        // different direction means no addition
        if (dir && dir_value < 0) {
          temp = 0;
        }
        if (!dir && dir_value > 0) {
          temp = 0;
        }
      }

      result += temp;
    }
  }
  record[field] = std::to_string(result);
}

/**
 * @brief Child granularity's field sum, skipping empty fields, assuming double
 *
 */
extern "C" void P_childsum_d(std::string& option, nlohmann::json& record,
                             const std::string& granularity, const std::string& key,
                             const std::string& field) {
  // option contains out_pkt field name
  // idx contains flow idx
  double result = 0;
  std::string child_g = fpnt::d->g_lvs[fpnt::d->g_lv_idx[granularity] - 1];
  for (auto& child_key : fpnt::d->out_child_keys[granularity][key]) {
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
extern "C" void P_childmean(std::string& option, nlohmann::json& record,
                            const std::string& granularity, const std::string& key,
                            const std::string& field) {
  // option contains out_pkt field name
  // idx contains flow idx
  double result = 0.0f;
  std::string child_g = fpnt::d->g_lvs[fpnt::d->g_lv_idx[granularity] - 1];
  size_t count = 0;
  for (auto& child_key : fpnt::d->out_child_keys[granularity][key]) {
    nlohmann::json& cnt = fpnt::d->out[child_g][child_key];
    if (!cnt[option].is_null()) {
      std::string val_str = cnt[option].get<std::string>();
      result += atof(val_str.c_str());
      count++;
    }
  }

  if (count > 0) result /= count;

  record[field] = std::to_string(result);
}

/**
 * @brief Child granularity's field aggregation, without skipping empty fields
 *
 */
extern "C" void P_childstdev(std::string& option, nlohmann::json& record,
                             const std::string& granularity, const std::string& key,
                             const std::string& field) {
  // option contains out_pkt field name
  // idx contains flow idx
  double mean = 0.0f;

  std::vector<double> stat;
  std::string child_g = fpnt::d->g_lvs[fpnt::d->g_lv_idx[granularity] - 1];
  size_t count = 0;
  for (auto& child_key : fpnt::d->out_child_keys[granularity][key]) {
    nlohmann::json& cnt = fpnt::d->out[child_g][child_key];
    if (!cnt[option].is_null()) {
      std::string val_str = cnt[option].get<std::string>();
      double cur_value = atof(val_str.c_str());
      stat.push_back(cur_value);
      mean += cur_value;
      count++;
    }
  }

  if (count <= 1) {  // undefined value
    record[field] = std::to_string(-1);
    return;
  }

  // always count > 0
  mean /= count;

  double sampled_standard_deviation = 0.0f;
  for (auto& cur_value : stat) {
    double deviation = cur_value - mean;
    sampled_standard_deviation += deviation * deviation;
  }

  sampled_standard_deviation /= count - 1;  // sampled!
  sampled_standard_deviation = sqrt(sampled_standard_deviation);

  record[field] = std::to_string(sampled_standard_deviation);
}

/**
 * @brief Child granularity's field max, assuming double
 *
 */
extern "C" void P_childmax_d(std::string& option, nlohmann::json& record,
                             const std::string& granularity, const std::string& key,
                             const std::string& field) {
  // option contains out_pkt field name
  // idx contains flow idx
  double result = std::numeric_limits<double>::lowest();
  std::string child_g = fpnt::d->g_lvs[fpnt::d->g_lv_idx[granularity] - 1];
  for (auto& child_key : fpnt::d->out_child_keys[granularity][key]) {
    nlohmann::json& cnt = fpnt::d->out[child_g][child_key];
    if (!cnt[option].is_null()) {
      std::string val_str = cnt[option].get<std::string>();
      double cur_value = atof(val_str.c_str());
      if (cur_value > result) result = cur_value;
    }
  }
  record[field] = std::to_string(result);
}

/**
 * @brief Child granularity's field min, assuming double
 *
 */
extern "C" void P_childmin_d(std::string& option, nlohmann::json& record,
                             const std::string& granularity, const std::string& key,
                             const std::string& field) {
  // option contains out_pkt field name
  // idx contains flow idx
  double result = std::numeric_limits<double>::max();
  std::string child_g = fpnt::d->g_lvs[fpnt::d->g_lv_idx[granularity] - 1];
  for (auto& child_key : fpnt::d->out_child_keys[granularity][key]) {
    nlohmann::json& cnt = fpnt::d->out[child_g][child_key];
    if (!cnt[option].is_null()) {
      std::string val_str = cnt[option].get<std::string>();
      double cur_value = atof(val_str.c_str());
      if (cur_value < result) result = cur_value;
    }
  }
  record[field] = std::to_string(result);
}

/**
 * @brief Child granularity's field min, assuming double, update only when non-zero value found
 *
 */
extern "C" void P_childnzmin_d(std::string& option, nlohmann::json& record,
                               const std::string& granularity, const std::string& key,
                               const std::string& field) {
  // option contains out_pkt field name
  // idx contains flow idx
  double result = std::numeric_limits<double>::max();
  std::string child_g = fpnt::d->g_lvs[fpnt::d->g_lv_idx[granularity] - 1];
  for (auto& child_key : fpnt::d->out_child_keys[granularity][key]) {
    nlohmann::json& cnt = fpnt::d->out[child_g][child_key];
    if (!cnt[option].is_null()) {
      std::string val_str = cnt[option].get<std::string>();
      double cur_value = atof(val_str.c_str());
      if (cur_value > 0 && cur_value < result) result = cur_value;
    }
  }
  record[field] = std::to_string(result);
}

/**
 * @brief Child granularity's field min, assuming double
 *
 */
extern "C" void P_childmaxdiff_d(std::string& option, nlohmann::json& record,
                                 const std::string& granularity, const std::string& key,
                                 const std::string& field) {
  // option contains out_pkt field name
  // idx contains flow idx
  double max = std::numeric_limits<double>::lowest();
  double min = std::numeric_limits<double>::max();
  std::string child_g = fpnt::d->g_lvs[fpnt::d->g_lv_idx[granularity] - 1];
  for (auto& child_key : fpnt::d->out_child_keys[granularity][key]) {
    nlohmann::json& cnt = fpnt::d->out[child_g][child_key];
    if (!cnt[option].is_null()) {
      std::string val_str = cnt[option].get<std::string>();
      double cur_value = atof(val_str.c_str());
      if (cur_value > max) max = cur_value;
      if (cur_value < min) min = cur_value;
    }
  }
  record[field] = std::to_string(max - min);
}

/**
 * @brief Child granularity's field max, assuming long long
 *
 */
extern "C" void P_childmax_ll(std::string& option, nlohmann::json& record,
                              const std::string& granularity, const std::string& key,
                              const std::string& field) {
  // option contains out_pkt field name
  // idx contains flow idx
  long long result = std::numeric_limits<long long>::lowest();
  std::string child_g = fpnt::d->g_lvs[fpnt::d->g_lv_idx[granularity] - 1];
  for (auto& child_key : fpnt::d->out_child_keys[granularity][key]) {
    nlohmann::json& cnt = fpnt::d->out[child_g][child_key];
    if (!cnt[option].is_null()) {
      std::string val_str = cnt[option].get<std::string>();
      long long cur_value = atoll(val_str.c_str());
      if (cur_value > result) result = cur_value;
    }
  }
  record[field] = std::to_string(result);
}

/**
 * @brief Child granularity's field min, assuming long long
 *
 */
extern "C" void P_childmin_ll(std::string& option, nlohmann::json& record,
                              const std::string& granularity, const std::string& key,
                              const std::string& field) {
  // option contains out_pkt field name
  // idx contains flow idx
  long long result = std::numeric_limits<long long>::max();
  std::string child_g = fpnt::d->g_lvs[fpnt::d->g_lv_idx[granularity] - 1];
  for (auto& child_key : fpnt::d->out_child_keys[granularity][key]) {
    nlohmann::json& cnt = fpnt::d->out[child_g][child_key];
    if (!cnt[option].is_null()) {
      std::string val_str = cnt[option].get<std::string>();
      long long cur_value = atoll(val_str.c_str());
      if (cur_value < result) result = cur_value;
    }
  }
  record[field] = std::to_string(result);
}
