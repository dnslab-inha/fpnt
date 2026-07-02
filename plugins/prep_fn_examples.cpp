#include <algorithm>
#include <nlohmann/json.hpp>
#include <string>
#include <tuple>
#include <utility>

#include "default_keygen.h"
#include <fpnt/plugin_context.h>
#include "util_plugins.h"

extern "C" void P_debug(fpnt::PluginContext& ctx) {
  std::cout << "ctx.getField() (name): " << ctx.getField() << "\t";

  if (ctx.getRecord()[ctx.getField()].is_null()) {
    std::cout << "This ctx.getField() is currently null!" << std::endl;
    return;
  }

  std::cout << "ctx.getField() (value) : " << ctx.getRecord()[ctx.getField()].get<std::string>() << "\t";
  std::cout << "ctx.getField() (value; without get) : " << ctx.getRecord()[ctx.getField()] << "\t";
  std::cout << "Option: " << ctx.getOption() << "\t";
  std::cout << "Out Record: " << ctx.getRecord().dump() << "\t";
  std::cout << "Mapper: ";
  auto x = ctx.getInMap().getFields();
  for (size_t i = 0; i < x.size(); i++) {
    std::cout << x[i];
    if (i == x.size() - 1)
      std::cout << "\t";
    else
      std::cout << ", ";
  }
  std::cout << "In Packet Index (idx): " << std::to_string(ctx.getRecord()["__in_idx"].get<size_t>())
            << std::endl;
  std::cout << "Out Index (idx): " << std::to_string(ctx.getOutKey2Idx().at(ctx.getGranularity()).at(ctx.getKey()))
            << std::endl;
  std::cout << "Dispatcher pointer: " << &ctx << std::endl;
  std::cout << "Dispatcher in_pkts size: " << ctx.getInPkts().size() << std::endl;
  std::cout << "Accessing in_pkts using idx: " << ctx.getInPkts()[ctx.getRecord()["__in_idx"]].dump()
            << std::endl;
}

extern "C" void P_cpy(fpnt::PluginContext& ctx) {
  //    auto x = ctx.getInMap().getFields();

  //    if (&map == &ctx->map_pkt)
  //    std::cout << "Out " << ctx.getField() << " Opt " << ctx.getOption() << " ptr " << ctx << " idx " << idx <<
  //    " sz " << ctx.getInPkts().size() << std::endl; std::cout << ctx.getInPkts()[idx].dump() <<
  //    std::endl; std::cout << ctx.getInPkts()[idx][ctx.getOption()] << std::endl; std::cout <<
  //    ctx.getRecord().dump() << std::endl;
  // if no ctx.getOption(), the given fieldname is assumed to be the same as in the input ctx.getField().
  std::string fieldname = ctx.getOption();
  if (fieldname == "") fieldname = ctx.getField();

  const size_t idx = ctx.getRecord()["__in_idx"].get<size_t>();
  if (ctx.getInPkts()[idx][fieldname].is_null())
    ctx.getRecord()[ctx.getField()] = "";
  else
    ctx.getRecord()[ctx.getField()] = ctx.getInPkts()[idx][fieldname].get<std::string>();
}

extern "C" void P_move(fpnt::PluginContext& ctx) {
  // if no ctx.getOption(), the given fieldname is assumed to be the same as in the input ctx.getField().
  std::string fieldname = ctx.getOption();
  if (fieldname == "") fieldname = ctx.getField();
  const size_t idx = ctx.getRecord()["__in_idx"];
  ctx.getRecord()[ctx.getField()] = ctx.getInPkts()[idx][fieldname];
}

extern "C" void P_diff_d(fpnt::PluginContext& ctx) {
  // parsing
  std::string start_key;
  std::string end_key;
  size_t colon_pos = ctx.getOption().find(':');

  if (colon_pos == std::string::npos) {
    throw std::invalid_argument("Option string must be in 'start_key:end_key' format.");
  }

  start_key = ctx.getOption().substr(0, colon_pos);
  end_key = ctx.getOption().substr(colon_pos + 1);

  // error check
  if (ctx.getRecord().find(start_key) == ctx.getRecord().end() || ctx.getRecord().find(end_key) == ctx.getRecord().end()) {
    throw std::runtime_error("One or both keys (" + start_key + ", " + end_key
                             + ") not found in ctx.getRecord() map.");
  }

  const auto& start_str = ctx.getRecord()[start_key].get_ref<const std::string&>();
  const auto& end_str = ctx.getRecord()[end_key].get_ref<const std::string&>();

  // 3. Convert string to double
  double start_time;
  double end_time;

  try {
    start_time = std::stod(start_str);
    end_time = std::stod(end_str);
  } catch (const std::exception& e) {
    throw std::runtime_error("Failed to convert one or both values to double: "
                             + std::string(e.what()));
  }

  // 4. Calculate time difference: end_time - start_time
  double difference = end_time - start_time;

  // 5. Convert result to string and save to ctx.getRecord()[ctx.getField()]
  ctx.getRecord()[ctx.getField()] = std::to_string(difference);
}

/**
 * @brief Child ctx.getGranularity()'s ctx.getField() aggregation, without skipping empty fields
 *
 */
extern "C" void P_childagg(fpnt::PluginContext& ctx) {
  // ctx.getOption() contains out_pkt ctx.getField() name
  // idx contains flow idx
  std::string result = "";
  bool first = true;
  
  const auto& opt = ctx.getOption();
  for (auto& child_key : ctx.getChildKeys()) {
    if (first) {
      first = false;
    } else {
      result += ",";
    }
    nlohmann::json& cnt = ctx.getChildRecord(child_key);
    auto& val = cnt[opt];
    if (!val.is_null()) result += val.get<std::string>();
  }
  ctx.getRecord()[ctx.getField()] = result;
}

/**
 * @brief Child ctx.getGranularity()'s ctx.getField() aggregation, ordered by __real_arrival_order, without skipping
 * empty fields
 *
 */
extern "C" void P_childagg_real_arrival_order(fpnt::PluginContext& ctx) {
  
  std::vector<std::pair<size_t, std::string>> ordered_vals;

  const auto& opt = ctx.getOption();
  for (auto& child_key : ctx.getChildKeys()) {
    nlohmann::json& cnt = ctx.getChildRecord(child_key);

    if (cnt["__real_arrival_order"].is_null()) {
      std::cerr << "P_childagg_real_arrival_order: Missing __real_arrival_order in child ctx.getRecord()!"
                << std::endl;
      exit(1);
    }

    size_t order = cnt["__real_arrival_order"].get<size_t>();
    std::string val_str = "";
    auto& val = cnt[opt];
    if (!val.is_null()) {
      val_str = val.get<std::string>();
    }
    ordered_vals.push_back({order, val_str});
  }

  std::sort(ordered_vals.begin(), ordered_vals.end(),
            [](const std::pair<size_t, std::string>& a, const std::pair<size_t, std::string>& b) {
              return a.first < b.first;
            });

  std::string result = "";
  for (size_t i = 0; i < ordered_vals.size(); ++i) {
    if (i > 0) result += ",";
    result += ordered_vals[i].second;
  }
  ctx.getRecord()[ctx.getField()] = result;
}

/**
 * @brief Packet ctx.getField() aggregation for flow, with skipping empty fields
 *
 */
extern "C" void P_skipchildagg(fpnt::PluginContext& ctx) {
  // ctx.getOption() contains out_pkt ctx.getField() name
  // idx contains flow idx
  std::string result = "";
  bool first = true;
  
  const auto& opt = ctx.getOption();
  for (auto& child_key : ctx.getChildKeys()) {
    nlohmann::json& cnt = ctx.getChildRecord(child_key);
    auto& val = cnt[opt];
    if (!val.is_null() && val != "") {
      if (first) {
        first = false;
      } else {
        result += ",";
      }

      result += val.get<std::string>();
    }
  }
  ctx.getRecord()[ctx.getField()] = result;
}

/**
 * @brief Interarrival Time Sequence for Flow
 *
 */
extern "C" void P_iat(fpnt::PluginContext& ctx) {
  // ctx.getOption() contains out_pkt ctx.getField() name
  // idx contains flow idx
  std::string result = "";
  std::vector<double> arrival_times;

  const auto& opt = ctx.getOption();
  for (auto& pkt_key : ctx.getKeys(ctx.getKey(), ctx.getGranularity(), "pkt")) {
    nlohmann::json& cnt = ctx.getRecordByGranularity("pkt", pkt_key);
    auto& val = cnt[opt];
    if (val.is_null()) {
      std::cerr << "P_iat4flow: Empty arrival time value!" << std::endl;
      exit(1);
    }

    double cnt_arrival_time = stod(val.get<std::string>());
    arrival_times.push_back(cnt_arrival_time);
  }

  std::vector<double> iats;
  if (arrival_times.size() > 1) {
    for (size_t i = 1; i < arrival_times.size(); ++i) {
      iats.push_back(arrival_times[i] - arrival_times[i - 1]);
    }

    // std::cout << "IATs: ";
    // for (const auto& iat : iats) {
    //   std::cout << iat << ", ";
    // }
    // std::cout << std::endl;

    ctx.getRecord()[ctx.getField()] = vectorToString(iats);
  } else {
    ctx.getRecord()[ctx.getField()] = "";
  }
}

/**
 * @brief Interarrival Time Sequence for Flow with Arrival Order Correction
 *
 */
extern "C" void P_iat_correct(fpnt::PluginContext& ctx) {
  std::vector<std::pair<std::string, double>> ordered_arrivals;

  const auto& opt = ctx.getOption();
  for (auto& pkt_key : ctx.getKeys(ctx.getKey(), ctx.getGranularity(), "pkt")) {
    nlohmann::json& cnt = ctx.getRecordByGranularity("pkt", pkt_key);
    auto& val = cnt[opt];
    if (val.is_null()) {
      std::cerr << "P_iat_correct: Empty arrival time value!" << std::endl;
      exit(1);
    }

    double cnt_arrival_time = std::stod(val.get<std::string>());
    ordered_arrivals.push_back({pkt_key, cnt_arrival_time});
  }

  std::sort(ordered_arrivals.begin(), ordered_arrivals.end(),
            [](const std::pair<std::string, double>& a, const std::pair<std::string, double>& b) {
              return a.second < b.second;
            });

  std::vector<double> iats;
  for (size_t i = 0; i < ordered_arrivals.size(); ++i) {
    ctx.getRecordByGranularity("pkt", ordered_arrivals[i].first)["__real_arrival_order"] = i;
    if (i > 0) {
      iats.push_back(ordered_arrivals[i].second - ordered_arrivals[i - 1].second);
    }
  }

  if (ordered_arrivals.size() > 1) {
    ctx.getRecord()[ctx.getField()] = vectorToString(iats);
  } else {
    ctx.getRecord()[ctx.getField()] = "";
  }
}

/**
 * @brief Interarrival Time Sequence for Flowset defined in CBSeq
 *
 */
extern "C" void P_iat_cbseq(fpnt::PluginContext& ctx) {
  // ctx.getOption() contains flow's start time ctx.getField() name
  // idx contains flow idx
  std::string result = "";
  std::vector<double> start_times;

  const auto& opt = ctx.getOption();
  for (auto& flow_key : ctx.getKeys(ctx.getKey(), ctx.getGranularity(), "flow")) {
    nlohmann::json& cnt = ctx.getRecordByGranularity("flow", flow_key);
    // std::cout << "flowkey: " << flow_key << std::endl;
    // std::cout << "ctx.getOption(): " << ctx.getOption() << std::endl;
    // std::cout << "ctx.getField(): " << cnt[ctx.getOption()].get<std::string>() << std::endl;
    auto& val = cnt[opt];
    if (val.is_null()) {
      std::cerr << "P_iat_cbseq: Empty arrival time value!" << std::endl;
      exit(1);
    }

    double cnt_start_time = stod(val.get<std::string>());
    start_times.push_back(cnt_start_time);
  }

  std::vector<double> iats;
  iats.push_back(0);
  if (start_times.size() > 1) {
    for (size_t i = 1; i < start_times.size(); ++i) {
      iats.push_back(start_times[i] - start_times[i - 1]);
    }
  }

  ctx.getRecord()[ctx.getField()] = vectorToString(iats);
}

/**
 * @brief Return Child count
 *
 */
extern "C" void P_childcount(fpnt::PluginContext& ctx) {
  ctx.getRecord()[ctx.getField()] = std::to_string(ctx.getChildKeys().size());
}

/**
 * @brief Return Child count if the value is true
 *
 */
extern "C" void P_childcountTrue(fpnt::PluginContext& ctx) {
  // ctx.getOption() contains out_pkt ctx.getField() name
  // idx contains flow idx
  std::string result = "";
  size_t count = 0;
  
  const auto& opt = ctx.getOption();
  for (auto& child_key : ctx.getChildKeys()) {
    nlohmann::json& cnt = ctx.getChildRecord(child_key);
    if (cnt[opt] == "True") count++;
  }

  ctx.getRecord()[ctx.getField()] = std::to_string(count);
}

extern "C" void P_childcountFalse(fpnt::PluginContext& ctx) {
  // ctx.getOption() contains out_pkt ctx.getField() name
  // idx contains flow idx
  std::string result = "";
  size_t count = 0;
  
  const auto& opt = ctx.getOption();
  for (auto& child_key : ctx.getChildKeys()) {
    nlohmann::json& cnt = ctx.getChildRecord(child_key);
    if (cnt[opt] == "False") count++;
  }

  ctx.getRecord()[ctx.getField()] = std::to_string(count);
}

/**
 * @brief Packet count for any granuality (without packet)
 *
 */
extern "C" void P_pktcount(fpnt::PluginContext& ctx) {
  ctx.getRecord()[ctx.getField()] = std::to_string(ctx.getKeys(ctx.getKey(), ctx.getGranularity(), "pkt").size());
}

/**
 * @brief Packet ctx.getField() aggregation for flowset, without skipping empty fields
 *
 */
extern "C" void P_pf_agg(fpnt::PluginContext& ctx) {
  // ctx.getOption() contains out_pkt ctx.getField() name
  // idx contains flow idx
  std::string result = "";
  bool first = true;
  const auto& opt = ctx.getOption();
  for (auto& pkt_key : ctx.getKeys(ctx.getKey(), ctx.getGranularity(), "pkt")) {
    if (first) {
      first = false;
    } else {
      result += ",";
    }
    auto& val = ctx.getRecordByGranularity("pkt", pkt_key)[opt];
    if (!val.is_null())
      result += val.get<std::string>();
  }
  ctx.getRecord()[ctx.getField()] = result;
}

/**
 * @brief Packet ctx.getField() aggregation for flowset, with skipping empty fields
 *
 */
extern "C" void P_skip_pf_agg(fpnt::PluginContext& ctx) {
  // ctx.getOption() contains out_pkt ctx.getField() name
  // idx contains flow idx
  std::string result = "";
  bool first = true;
  const auto& opt = ctx.getOption();
  for (auto& pkt_key : ctx.getKeys(ctx.getKey(), ctx.getGranularity(), "pkt")) {
    nlohmann::json& cnt = ctx.getRecordByGranularity("pkt", pkt_key);
    auto& val = cnt[opt];
    if (!val.is_null() && val != "") {
      if (first) {
        first = false;
      } else {
        result += ",";
      }
      result += val.get<std::string>();
    }
  }
  ctx.getRecord()[ctx.getField()] = result;
}

/** P_fill1: fill if empty
 *
 */
extern "C" void P_fill1(fpnt::PluginContext& ctx) {
  const size_t idx = ctx.getRecord()["__in_idx"];
  if (ctx.getRecord()[ctx.getField()] == "") ctx.getRecord()[ctx.getField()] = ctx.getInPkts()[idx][ctx.getOption()];
}

/** P_firstcpy4flow: copy the first child's value for flow (typically expecting that the packets in
 * the flow have the same value)
 *
 */
extern "C" void P_firstcpy(fpnt::PluginContext& ctx) {
  
  auto first_child_key = ctx.getChildKeys()[0];
  ctx.getRecord()[ctx.getField()] = ctx.getChildRecord(first_child_key)[ctx.getOption()];
}

/** P_fillOpt: fill with ctx.getOption() value
 *
 */
extern "C" void P_fillOpt(fpnt::PluginContext& ctx) {
  ctx.getRecord()[ctx.getField()] = ctx.getOption();
}

/** P_saveKey: save the ctx.getKey() corresponding to "ctx.getOption()" ctx.getGranularity(), of the current ctx.getRecord(), to the
 * ctx.getField() value Please note this function does not check the availability of such ctx.getKey().
 *
 */
extern "C" void P_saveKey(fpnt::PluginContext& ctx) {
  ctx.getRecord()[ctx.getField()] = ctx.getRecord()["__" + ctx.getOption() + "_key"];
}

/** P_saveFlowKey: save the corresponding flow ctx.getRecord()'s ctx.getKey(), of the current ctx.getRecord(), to the ctx.getField()
 * value Please note this function does not check the availability of such ctx.getKey().
 *
 */
extern "C" void P_saveFlowKey(fpnt::PluginContext& ctx) {
  ctx.getRecord()[ctx.getField()] = ctx.getRecord()["__flow_key"];
}

/** P_saveFlowsetKey: save the corresponding flowset ctx.getRecord()'s ctx.getKey(), of the current ctx.getRecord(), to the
 * ctx.getField() value Please note this function does not check the availability of such ctx.getKey().
 *
 */
extern "C" void P_saveFlowsetKey(fpnt::PluginContext& ctx) {
  ctx.getRecord()[ctx.getField()] = ctx.getRecord()["__flowset_key"];
}

/** P_savePktKey: save the corresponding pkt's ctx.getKey(), of the current ctx.getRecord(), to the ctx.getField() value
 * Please note this function does not check the availability of such ctx.getKey(), but due to the internal
 * design of fpnt, this ctx.getKey() must be available.
 *
 */
extern "C" void P_savePktKey(fpnt::PluginContext& ctx) {
  ctx.getRecord()[ctx.getField()] = ctx.getRecord()["__pkt_key"];
}

/** P_saveDir: save the corresponding dir, of the current ctx.getRecord(), to the ctx.getField() value
 * Please note this function does not check the availability of such ctx.getKey(), but due to the internal
 * design of fpnt, this ctx.getKey() must be available.
 *
 */
extern "C" void P_saveDir(fpnt::PluginContext& ctx) {
  ctx.getRecord()[ctx.getField()] = ctx.getRecord()["__dir"];
}

/** P_dir: calculate packet direction (either +1 or -1) based on genKey_flow_default (a stateless
 * flow ctx.getKey() generation). That is, the first IP address of the flow ctx.getKey() is the smaller one, not the
 * client's IP address. Therefore, When you want to obtain "the TCP style" packet direction
 * sequence, you need to check whether the first packet's direction is +1 or -1. If it is -1, the
 * sequence values should be multiplied by -1.
 */
extern "C" void P_dir(fpnt::PluginContext& ctx) {
  const size_t idx = ctx.getRecord()["__in_idx"];
  // std::cout << ctx.getRecord().dump() << std::endl;
  const auto& flow_key = ctx.getRecord()["__flow_key"].get_ref<const std::string&>();

  std::string ipsrc = ctx.getInPkts()[idx]["_ws.col.def_src"].get<std::string>();

  size_t l;
  if ((l = ipsrc.find(',')) != std::string::npos) {
    ipsrc = ipsrc.substr(0, l);
  }

  if (ipsrc == "") {
    ctx.getRecord()["__dir"] = "0";  // unexpected value
    return;
  }

  size_t comma_pos = flow_key.find(',');
  if (comma_pos == std::string::npos) {
    ctx.getRecord()["__dir"] = "0";
    return;
  }

  std::string ep1 = flow_key.substr(0, comma_pos);
  std::string ep2 = flow_key.substr(comma_pos + 1);

  size_t slash_pos = ep2.find('/');
  if (slash_pos != std::string::npos) {
    ep2 = ep2.substr(0, slash_pos);
  }

  size_t ep1_colon = ep1.rfind(':');
  size_t ep2_colon = ep2.rfind(':');

  if (ep1_colon == std::string::npos || ep2_colon == std::string::npos) {
    ctx.getRecord()["__dir"] = "0";
    return;
  }

  std::string ip1 = ep1.substr(0, ep1_colon);
  std::string ip2 = ep2.substr(0, ep2_colon);

  if (ip1 != ip2) {
    if (ipsrc == ip1) {
      ctx.getRecord()["__dir"] = "+1";
    } else if (ipsrc == ip2) {
      ctx.getRecord()["__dir"] = "-1";
    } else {
      ctx.getRecord()["__dir"] = "0";
    }
  } else {
    std::string dstport = ctx.getInPkts()[idx]["tcp.dstport"].get<std::string>();
    if (ctx.getInPkts()[idx]["udp.dstport"].get<std::string>() != "") {
      dstport = ctx.getInPkts()[idx]["udp.dstport"].get<std::string>();
    }

    if (dstport == "") {      // both tcp and udp has empty dstport
      ctx.getRecord()["__dir"] = "0";  // unexpected value
      return;
    }

    std::string port2 = ep2.substr(ep2_colon + 1);

    if (dstport == port2) {
      ctx.getRecord()["__dir"] = "+1";
    } else {
      ctx.getRecord()["__dir"] = "-1";
    }
  }
}

/** P_dir_ipv4: calculate packet direction (either +1 or -1) based on genKey_flow_ipv4 (a stateless
 * flow ctx.getKey() generation). That is, the first IP address of the flow ctx.getKey() is the smaller one, not the
 * client's IP address. Therefore, When you want to obtain "the TCP style" packet direction
 * sequence, you need to check whether the first packet's direction is +1 or -1. If it is -1, the
 * sequence values should be multiplied by -1.
 */
extern "C" void P_dir_ipv4(fpnt::PluginContext& ctx) {
  const size_t idx = ctx.getRecord()["__in_idx"];
  // std::cout << ctx.getRecord().dump() << std::endl;
  const auto& flow_key = ctx.getRecord()["__flow_key"].get_ref<const std::string&>();

  if (flow_key.length() >= 5 && flow_key.substr(flow_key.length() - 5, 5) == "_IPv6") {
    ctx.getRecord()["__dir"] = "0";  // unexpected value
    return;
  }

  std::string ipsrc = ctx.getInPkts()[idx]["ip.src"].get<std::string>();
  if (ipsrc == "") {
    ctx.getRecord()["__dir"] = "0";  // unexpected value
    return;
  }

  size_t comma_pos = flow_key.find(',');
  if (comma_pos == std::string::npos) {
    ctx.getRecord()["__dir"] = "0";
    return;
  }

  std::string ep1 = flow_key.substr(0, comma_pos);
  std::string ep2 = flow_key.substr(comma_pos + 1);

  size_t slash_pos = ep2.find('/');
  if (slash_pos != std::string::npos) {
    ep2 = ep2.substr(0, slash_pos);
  }

  size_t ep1_colon = ep1.rfind(':');
  size_t ep2_colon = ep2.rfind(':');

  if (ep1_colon == std::string::npos || ep2_colon == std::string::npos) {
    ctx.getRecord()["__dir"] = "0";
    return;
  }

  std::string ip1 = ep1.substr(0, ep1_colon);
  std::string ip2 = ep2.substr(0, ep2_colon);

  if (ip1 != ip2) {
    if (ipsrc == ip1) {
      ctx.getRecord()["__dir"] = "+1";
    } else if (ipsrc == ip2) {
      ctx.getRecord()["__dir"] = "-1";
    } else {
      ctx.getRecord()["__dir"] = "0";
    }
  } else {
    std::string dstport = ctx.getInPkts()[idx]["tcp.dstport"].get<std::string>();
    if (ctx.getInPkts()[idx]["udp.dstport"].get<std::string>() != "") {
      dstport = ctx.getInPkts()[idx]["udp.dstport"].get<std::string>();
    }

    if (dstport == "") {      // both tcp and udp has empty dstport
      ctx.getRecord()["__dir"] = "0";  // unexpected value
      return;
    }

    std::string port2 = ep2.substr(ep2_colon + 1);

    if (dstport == port2) {
      ctx.getRecord()["__dir"] = "+1";
    } else {
      ctx.getRecord()["__dir"] = "-1";
    }
  }
}