#include <limits>
#include <nlohmann/json.hpp>
#include <string>
#include <tuple>
#include <utility>

#include "default_keygen.h"
#include <fpnt/plugin_context.h>
#include "util_plugins.h"

/**
 * @brief Same ctx.getGranularity()'s ctx.getField() max, assuming double
 *
 */
extern "C" void P_max_d(fpnt::PluginContext& ctx) {
  nlohmann::json& cnt = ctx.getRecord();
  std::string vectorString = cnt[ctx.getOption()];
  std::vector<double> values = stringToVector(vectorString);

  double result = std::numeric_limits<double>::lowest();
  for (const auto& val : values) {
    if (val > result) result = val;
  }

  if (result == std::numeric_limits<double>::lowest()) {
    // No valid values found
    ctx.getRecord()[ctx.getField()] = "";
  } else {
    ctx.getRecord()[ctx.getField()] = std::to_string(result);
  }
}

/**
 * @brief Same ctx.getGranularity()'s ctx.getField() min, assuming double
 *
 */
extern "C" void P_min_d(fpnt::PluginContext& ctx) {
  nlohmann::json& cnt = ctx.getRecord();
  std::string vectorString = cnt[ctx.getOption()];
  std::vector<double> values = stringToVector(vectorString);

  double result = std::numeric_limits<double>::max();
  for (const auto& val : values) {
    if (val < result) result = val;
  }

  if (result == std::numeric_limits<double>::max()) {
    // No valid values found
    ctx.getRecord()[ctx.getField()] = "";
  } else {
    ctx.getRecord()[ctx.getField()] = std::to_string(result);
  }
}

/**
 * @brief Child ctx.getGranularity()'s ctx.getField() sum, skipping empty fields; assuming long long
 *
 */
extern "C" void P_childsum_ll(fpnt::PluginContext& ctx) {
  // ctx.getOption() contains out_pkt ctx.getField() name
  // however, postfix '+' or '-' can be possible (assuming that ctx.getField() name does not allow postfix
  // '+' or '-').
  std::string fieldname = ctx.getOption();
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
  
  for (auto& child_key : ctx.getChildKeys()) {
    nlohmann::json& cnt = ctx.getChildRecord(child_key);
    auto& val = cnt[fieldname];
    if (!val.is_null()) {
      const auto& val_str = val.get_ref<const std::string&>();
      long long temp = atoll(val_str.c_str());

      if (check_dir) {  // we should check direction
        long long dir_value = atoll(cnt["__dir"].get_ref<const std::string&>().c_str());
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
  ctx.getRecord()[ctx.getField()] = std::to_string(result);
}

/**
 * @brief Child ctx.getGranularity()'s ctx.getField() sum, skipping empty fields, assuming double
 *
 */
extern "C" void P_childsum_d(fpnt::PluginContext& ctx) {
  // ctx.getOption() contains out_pkt ctx.getField() name
  // idx contains flow idx
  double result = 0;
  
  const auto& opt = ctx.getOption();
  for (auto& child_key : ctx.getChildKeys()) {
    nlohmann::json& cnt = ctx.getChildRecord(child_key);
    auto& val = cnt[opt];
    if (!val.is_null()) {
      const auto& val_str = val.get_ref<const std::string&>();
      result += atof(val_str.c_str());
    }
  }
  ctx.getRecord()[ctx.getField()] = std::to_string(result);
}

/**
 * @brief Child ctx.getGranularity()'s ctx.getField() aggregation, without skipping empty fields
 *
 */
extern "C" void P_childmean(fpnt::PluginContext& ctx) {
  // ctx.getOption() contains out_pkt ctx.getField() name
  // idx contains flow idx
  double result = 0.0f;
  
  size_t count = 0;
  const auto& opt = ctx.getOption();
  for (auto& child_key : ctx.getChildKeys()) {
    nlohmann::json& cnt = ctx.getChildRecord(child_key);
    auto& val = cnt[opt];
    if (!val.is_null()) {
      const auto& val_str = val.get_ref<const std::string&>();
      result += atof(val_str.c_str());
      count++;
    }
  }

  if (count > 0) result /= count;

  ctx.getRecord()[ctx.getField()] = std::to_string(result);
}

/**
 * @brief Child ctx.getGranularity()'s ctx.getField() aggregation, without skipping empty fields
 *
 */
extern "C" void P_childstdev(fpnt::PluginContext& ctx) {
  // ctx.getOption() contains out_pkt ctx.getField() name
  // idx contains flow idx
  double mean = 0.0f;

  std::vector<double> stat;
  
  size_t count = 0;
  const auto& opt = ctx.getOption();
  for (auto& child_key : ctx.getChildKeys()) {
    nlohmann::json& cnt = ctx.getChildRecord(child_key);
    auto& val = cnt[opt];
    if (!val.is_null()) {
      const auto& val_str = val.get_ref<const std::string&>();
      double cur_value = atof(val_str.c_str());
      stat.push_back(cur_value);
      mean += cur_value;
      count++;
    }
  }

  if (count <= 1) {  // undefined value
    ctx.getRecord()[ctx.getField()] = std::to_string(-1);
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

  ctx.getRecord()[ctx.getField()] = std::to_string(sampled_standard_deviation);
}

/**
 * @brief Child ctx.getGranularity()'s ctx.getField() max, assuming double
 *
 */
extern "C" void P_childmax_d(fpnt::PluginContext& ctx) {
  // ctx.getOption() contains out_pkt ctx.getField() name
  // idx contains flow idx
  double result = std::numeric_limits<double>::lowest();
  
  const auto& opt = ctx.getOption();
  for (auto& child_key : ctx.getChildKeys()) {
    nlohmann::json& cnt = ctx.getChildRecord(child_key);
    auto& val = cnt[opt];
    if (!val.is_null()) {
      const auto& val_str = val.get_ref<const std::string&>();
      double cur_value = atof(val_str.c_str());
      if (cur_value > result) result = cur_value;
    }
  }
  ctx.getRecord()[ctx.getField()] = std::to_string(result);
}

/**
 * @brief Child ctx.getGranularity()'s ctx.getField() min, assuming double
 *
 */
extern "C" void P_childmin_d(fpnt::PluginContext& ctx) {
  // ctx.getOption() contains out_pkt ctx.getField() name
  // idx contains flow idx
  double result = std::numeric_limits<double>::max();
  
  const auto& opt = ctx.getOption();
  for (auto& child_key : ctx.getChildKeys()) {
    nlohmann::json& cnt = ctx.getChildRecord(child_key);
    auto& val = cnt[opt];
    if (!val.is_null()) {
      const auto& val_str = val.get_ref<const std::string&>();
      double cur_value = atof(val_str.c_str());
      if (cur_value < result) result = cur_value;
    }
  }
  ctx.getRecord()[ctx.getField()] = std::to_string(result);
}

/**
 * @brief Child ctx.getGranularity()'s ctx.getField() min, assuming double, update only when non-zero value found
 *
 */
extern "C" void P_childnzmin_d(fpnt::PluginContext& ctx) {
  // ctx.getOption() contains out_pkt ctx.getField() name
  // idx contains flow idx
  double result = std::numeric_limits<double>::max();
  
  const auto& opt = ctx.getOption();
  for (auto& child_key : ctx.getChildKeys()) {
    nlohmann::json& cnt = ctx.getChildRecord(child_key);
    auto& val = cnt[opt];
    if (!val.is_null()) {
      const auto& val_str = val.get_ref<const std::string&>();
      double cur_value = atof(val_str.c_str());
      if (cur_value > 0 && cur_value < result) result = cur_value;
    }
  }
  ctx.getRecord()[ctx.getField()] = std::to_string(result);
}

/**
 * @brief Child ctx.getGranularity()'s ctx.getField() min, assuming double
 *
 */
extern "C" void P_childmaxdiff_d(fpnt::PluginContext& ctx) {
  // ctx.getOption() contains out_pkt ctx.getField() name
  // idx contains flow idx
  double max = std::numeric_limits<double>::lowest();
  double min = std::numeric_limits<double>::max();
  
  const auto& opt = ctx.getOption();
  for (auto& child_key : ctx.getChildKeys()) {
    nlohmann::json& cnt = ctx.getChildRecord(child_key);
    auto& val = cnt[opt];
    if (!val.is_null()) {
      const auto& val_str = val.get_ref<const std::string&>();
      double cur_value = atof(val_str.c_str());
      if (cur_value > max) max = cur_value;
      if (cur_value < min) min = cur_value;
    }
  }
  ctx.getRecord()[ctx.getField()] = std::to_string(max - min);
}

/**
 * @brief Child ctx.getGranularity()'s ctx.getField() max, assuming long long
 *
 */
extern "C" void P_childmax_ll(fpnt::PluginContext& ctx) {
  // ctx.getOption() contains out_pkt ctx.getField() name
  // idx contains flow idx
  long long result = std::numeric_limits<long long>::lowest();
  
  const auto& opt = ctx.getOption();
  for (auto& child_key : ctx.getChildKeys()) {
    nlohmann::json& cnt = ctx.getChildRecord(child_key);
    auto& val = cnt[opt];
    if (!val.is_null()) {
      const auto& val_str = val.get_ref<const std::string&>();
      long long cur_value = atoll(val_str.c_str());
      if (cur_value > result) result = cur_value;
    }
  }
  ctx.getRecord()[ctx.getField()] = std::to_string(result);
}

/**
 * @brief Child ctx.getGranularity()'s ctx.getField() min, assuming long long
 *
 */
extern "C" void P_childmin_ll(fpnt::PluginContext& ctx) {
  // ctx.getOption() contains out_pkt ctx.getField() name
  // idx contains flow idx
  long long result = std::numeric_limits<long long>::max();
  
  const auto& opt = ctx.getOption();
  for (auto& child_key : ctx.getChildKeys()) {
    nlohmann::json& cnt = ctx.getChildRecord(child_key);
    auto& val = cnt[opt];
    if (!val.is_null()) {
      const auto& val_str = val.get_ref<const std::string&>();
      long long cur_value = atoll(val_str.c_str());
      if (cur_value < result) result = cur_value;
    }
  }
  ctx.getRecord()[ctx.getField()] = std::to_string(result);
}
