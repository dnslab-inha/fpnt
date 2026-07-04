#include <fpnt/plugin_context.h>

#include <charconv>
#include <nlohmann/json.hpp>
#include <regex>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

#include "default_keygen.h"
#include "util_plugins.h"

extern "C" void P_hex2dec(fpnt::PluginContext& ctx) {
  std::stringstream ss;
  ss << std::hex
     << (ctx.getRecord()[ctx.getField()].is_string()
             ? ctx.getRecord()[ctx.getField()].get<std::string>()
             : "");
  unsigned int x;
  ss >> x;
  ctx.getRecord()[ctx.getField()] = std::to_string(x);
}

extern "C" void P_plus(fpnt::PluginContext& ctx) {
  std::stringstream ss;
  ss << (ctx.getRecord()[ctx.getField()].is_string()
             ? ctx.getRecord()[ctx.getField()].get<std::string>()
             : "");
  unsigned int x;
  ss >> x;
  x += std::stoi(ctx.getOption());

  ctx.getRecord()[ctx.getField()] = std::to_string(x);
}

extern "C" void P_cal_no_angles(fpnt::PluginContext& ctx) {
  const auto& nc = (ctx.getRecord()["wlan.vht.mimo_control.nc"].is_string()
                        ? ctx.getRecord()["wlan.vht.mimo_control.nc"].get<std::string>()
                        : "");
  const auto& nr = (ctx.getRecord()["wlan.vht.mimo_control.nr"].is_string()
                        ? ctx.getRecord()["wlan.vht.mimo_control.nr"].get<std::string>()
                        : "");
  std::string nr_nc = nr + "_" + nc;

  if (nr_nc == "2_1" || nr_nc == "2_2")
    ctx.getRecord()[ctx.getField()] = "2";
  else if (nr_nc == "3_1")
    ctx.getRecord()[ctx.getField()] = "4";
  else if (nr_nc == "3_2" || nr_nc == "3_3" || nr_nc == "4_1")
    ctx.getRecord()[ctx.getField()] = "6";
  else if (nr_nc == "4_2")
    ctx.getRecord()[ctx.getField()] = "10";
  else if (nr_nc == "4_3" || nr_nc == "4_4")
    ctx.getRecord()[ctx.getField()] = "12";
}

extern "C" void P_comma2semicol(fpnt::PluginContext& ctx) {
  const auto& no_angles = ctx.getRecord()[ctx.getOption()].get_ref<const std::string&>();

  std::stringstream ss;
  unsigned int x;
  ss << no_angles;
  ss >> x;

  std::string original = (ctx.getRecord()[ctx.getField()].is_string()
                              ? ctx.getRecord()[ctx.getField()].get<std::string>()
                              : "");
  size_t pos = original.find(",", 0);
  size_t occurence = 0;
  while (pos != std::string::npos) {
    occurence++;
    if (occurence == x) {
      original[pos] = ';';
      occurence = 0;
    }
    pos = original.find(",", pos + 1);
  }

  ctx.getRecord()[ctx.getField()] = original;
}

// Helper function: removes leading and trailing whitespace from the string.
std::string trim2(const std::string& str) {
  size_t first = str.find_first_not_of(" \t\n\r");
  if (std::string::npos == first) {
    return str;
  }
  size_t last = str.find_last_not_of(" \t\n\r");
  return str.substr(first, (last - first + 1));
}

extern "C" void P_fast_bfm_fill(fpnt::PluginContext& ctx) {
  std::string original = (ctx.getRecord()[ctx.getField()].is_string()
                              ? ctx.getRecord()[ctx.getField()].get<std::string>()
                              : "");
  //    std::cout << original << std::endl;

  std::stringstream ss_blocks(original);
  std::string block;
  auto& bfm_record = ctx.getRecordByGranularity("bfm", ctx.getKey());

  // iterate the SCIDX block (e.g., "-122, φ11:41, φ21:34, ...")
  while (std::getline(ss_blocks, block, ';')) {
    std::string trimmed_block = trim2(block);
    if (trimmed_block.empty()) continue;

    // split the parameter block into one SCIDX integer and several ctx.getKey():value pairs.
    std::stringstream ss_parts(trimmed_block);
    std::string part;

    std::vector<std::string> parts;
    while (std::getline(ss_parts, part, ',')) {
      parts.push_back(trim2(part));
    }

    if (parts.empty()) continue;

    const std::string scidx_str = parts[0];
    try {
      // test whether SCIDX is valid or not
      std::stoi(scidx_str);
    } catch (const std::exception& e) {
      exit(1);
    }

    // iterate ctx.getKey():value pairs from part[1]
    for (size_t i = 1; i < parts.size(); ++i) {
      const std::string& kv_pair = parts[i];  // e.g. "φ11:41" " ψ21:6"

      size_t colon_pos = kv_pair.find(':');
      if (colon_pos == std::string::npos) {
        // even if invalid data is available, ignore.
        continue;
      }

      // ctx.getKey() value extraction
      std::string param_key = kv_pair.substr(0, colon_pos);
      std::string param_value_str = kv_pair.substr(colon_pos + 1);

      param_key = trim2(param_key);
      param_value_str = trim2(param_value_str);

      if (param_key.empty() || param_value_str.empty()) {
        continue;
      }

      // int value;
      // try {
      //     value = std::stoi(param_value_str);
      // } catch (const std::exception& e) {
      //     // even if invalid data is available, ignore.
      //     continue;
      // }

      // Create final mapping ctx.getKey(): "SCIDX: -122,φ11"
      std::string final_map_key = "SCIDX: " + scidx_str + "," + param_key;

      // std::cout << "ctx.getKey(): " << ctx.getKey() << " ctx.getField() " << final_map_key <<
      // std::endl;

      // 6. Save data
      // ctx.getRecordByGranularity("bfm", ctx.getKey())["SCIDX: -122,φ11"] = 41;
      bfm_record[final_map_key] = param_value_str;
    }
  }
}
extern "C" void P_bfm_fill(fpnt::PluginContext& ctx) {
  // std::cout << "P_bfm_find: "  << ctx.getField() << ", " << ctx.getKey() << std::endl;
  const std::string scidx_fieldname = "wlan.vht.compressed_beamforming_report.scidx";

  const std::string& cnt = ctx.getRecordByGranularity("pkt", ctx.getKey())[scidx_fieldname]
                               .get_ref<const std::string&>();

  // ctx.getOption() parsing: extract "SCIDX, Parameter_Name, Index"
  // for example: ctx.getOption() = "-122,phi,11"

  std::vector<std::string> option_parts;
  std::stringstream ss(ctx.getOption());
  std::string part;
  while (std::getline(ss, part, ',')) {
    option_parts.push_back(part);
  }

  if (option_parts.size() < 3) {
    std::cout << "error 1 " << std::endl;
    exit(1);  // error
  }

  // option_parts[0] is scidx (subcarrier) in integer (e.g., -122)
  // option_parts[1] is parameter name (e.g., phi)
  // option_parts[2] is parameter idx (e.g.: 11)

  const std::string target_scidx_str = option_parts[0];
  const std::string target_param_name = option_parts[1];  // phi or psi
  const std::string target_param_idx = option_parts[2];   // 11, 21, ...

  // target_param_key: the ctx.getKey() to find in the string 'cnt' (e.g.,: φ11); convert alphabet
  // (phi -> φ, psi -> ψ)
  std::string target_param_key;
  if (target_param_name == "phi") {  // φ (U+03C6)
    target_param_key = "\u03C6" + target_param_idx;
  } else if (target_param_name == "psi") {  // ψ (U+03C8)
    target_param_key = "\u03C8" + target_param_idx;
  } else {
    std::cout << "error 2 " << std::endl;
    exit(1);  // error
  }

  // cnt can be split using delimiter ";" and each line consists of one "scidx," and several
  // "ctx.getKey():value". example: ...;-122, φ11:41, φ21:34, ψ21:6, ...;...

  // regular expresson to extract
  std::regex scidx_block_regex("(" + target_scidx_str + ",[\\s]*)(.*?)(;|$)");
  std::smatch scidx_match;

  std::string params_block;
  if (std::regex_search(cnt, scidx_match, scidx_block_regex)) {
    // scidx_match[2] is the parameter block without scidx
    // e.g., "φ11:41, φ21:34, ψ21:6, ψ31:5, φ22:61, ψ32:3"
    params_block = scidx_match[2].str();
  } else {
    try {
      ctx.getRecord()[ctx.getField()] = "#N/A";
    } catch (const std::exception& e) {
      exit(1);
    }
    return;
  }

  // find target ctx.getKey()-value pair from the parameter block
  std::regex param_value_regex(target_param_key + ":(\\d+)");
  std::smatch value_match;

  std::string target_value_str;
  if (std::regex_search(params_block, value_match, param_value_regex)) {
    target_value_str = value_match[1].str();
  } else {
    try {
      ctx.getRecord()[ctx.getField()] = "#N/A";
    } catch (const std::exception& e) {
      exit(1);
    }
    return;
  }

  try {
    ctx.getRecord()[ctx.getField()] = target_value_str;
  } catch (const std::exception& e) {
    std::cout << "error 5" << std::endl;
    exit(1);  // error
  }
}