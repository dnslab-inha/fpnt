#include <nlohmann/json.hpp>
#include <string>
#include <tuple>
#include <utility>

#include "default_keygen.h"
#include "dispatcher_ptr.h"
#include "util_plugins.h"

extern "C" void P_debug(std::string& option, nlohmann::json& record, const std::string& granularity,
                        const std::string& key, const std::string& field) {
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
  for (size_t i = 0; i < x.size(); i++) {
    std::cout << x[i];
    if (i == x.size() - 1)
      std::cout << "\t";
    else
      std::cout << ", ";
  }
  std::cout << "In Packet Index (idx): " << std::to_string(record["__in_idx"].get<size_t>())
            << std::endl;
  std::cout << "Out Index (idx): " << std::to_string(fpnt::d->out_key2idx[granularity][key])
            << std::endl;
  std::cout << "Dispatcher pointer: " << fpnt::d << std::endl;
  std::cout << "Dispatcher in_pkts size: " << fpnt::d->in_pkts.size() << std::endl;
  std::cout << "Accessing in_pkts using idx: " << fpnt::d->in_pkts[record["__in_idx"]].dump()
            << std::endl;
}

extern "C" void P_cpy(std::string& option, nlohmann::json& record, const std::string& granularity,
                      const std::string& key, const std::string& field) {
  //    auto x = fpnt::d->in_map.getFields();

  //    if (&map == &fpnt::d->map_pkt)
  //    std::cout << "Out " << field << " Opt " << option << " ptr " << fpnt::d << " idx " << idx <<
  //    " sz " << fpnt::d->in_pkts.size() << std::endl; std::cout << fpnt::d->in_pkts[idx].dump() <<
  //    std::endl; std::cout << fpnt::d->in_pkts[idx][option] << std::endl; std::cout <<
  //    record.dump() << std::endl;
  // if no option, the given fieldname is assumed to be the same as in the input field.
  std::string fieldname = option;
  if (fieldname == "") fieldname = field;

  const size_t idx = record["__in_idx"].get<size_t>();
  if (fpnt::d->in_pkts[idx][fieldname].is_null())
    record[field] = "";
  else
    record[field] = fpnt::d->in_pkts[idx][fieldname].get<std::string>();
}

extern "C" void P_move(std::string& option, nlohmann::json& record, const std::string& granularity,
                       const std::string& key, const std::string& field) {
  // if no option, the given fieldname is assumed to be the same as in the input field.
  std::string fieldname = option;
  if (fieldname == "") fieldname = field;
  const size_t idx = record["__in_idx"];
  record[field] = std::move(fpnt::d->in_pkts[idx][fieldname]);
}

extern "C" void P_diff_d(std::string& option, nlohmann::json& record,
                         const std::string& granularity, const std::string& key,
                         const std::string& field) {
  // parsing
  std::string start_key;
  std::string end_key;
  size_t colon_pos = option.find(':');

  if (colon_pos == std::string::npos) {
    throw std::invalid_argument("Option string must be in 'start_key:end_key' format.");
  }

  start_key = option.substr(0, colon_pos);
  end_key = option.substr(colon_pos + 1);

  // error check
  if (record.find(start_key) == record.end() || record.find(end_key) == record.end()) {
    throw std::runtime_error("One or both keys (" + start_key + ", " + end_key
                             + ") not found in record map.");
  }

  const std::string start_str = record[start_key].get<std::string>();
  const std::string end_str = record[end_key].get<std::string>();

  // 3. 문자열을 double로 변환
  double start_time;
  double end_time;

  try {
    start_time = std::stod(start_str);
    end_time = std::stod(end_str);
  } catch (const std::exception& e) {
    throw std::runtime_error("Failed to convert one or both values to double: "
                             + std::string(e.what()));
  }

  // 4. 시간차 계산: end_time - start_time
  double difference = end_time - start_time;

  // 5. 결과를 문자열로 변환하여 record[field]에 저장
  record[field] = std::to_string(difference);
}

/**
 * @brief Child granularity's field aggregation, without skipping empty fields
 *
 */
extern "C" void P_childagg(std::string& option, nlohmann::json& record,
                           const std::string& granularity, const std::string& key,
                           const std::string& field) {
  // option contains out_pkt field name
  // idx contains flow idx
  std::string result = "";
  bool first = true;
  std::string child_g = fpnt::d->g_lvs[fpnt::d->g_lv_idx[granularity] - 1];
  for (auto& child_key : fpnt::d->out_child_keys[granularity][key]) {
    if (first) {
      first = false;
    } else {
      result += ",";
    }
    nlohmann::json& cnt = fpnt::d->out[child_g][child_key];
    if (!cnt[option].is_null()) result += cnt[option].get<std::string>();
  }
  record[field] = result;
}

/**
 * @brief Packet field aggregation for flow, with skipping empty fields
 *
 */
extern "C" void P_skipchildagg(std::string& option, nlohmann::json& record,
                               const std::string& granularity, const std::string& key,
                               const std::string& field) {
  // option contains out_pkt field name
  // idx contains flow idx
  std::string result = "";
  bool first = true;
  std::string child_g = fpnt::d->g_lvs[fpnt::d->g_lv_idx[granularity] - 1];
  for (auto& child_key : fpnt::d->out_child_keys[granularity][key]) {
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
extern "C" void P_iat(std::string& option, nlohmann::json& record, const std::string& granularity,
                      const std::string& key, const std::string& field) {
  // option contains out_pkt field name
  // idx contains flow idx
  std::string result = "";
  std::vector<double> arrival_times;

  for (auto& pkt_key : fpnt::get_keys(key, granularity, "pkt")) {
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

    // std::cout << "IATs: ";
    // for (const auto& iat : iats) {
    //   std::cout << iat << ", ";
    // }
    // std::cout << std::endl;

    record[field] = vectorToString(iats);
  } else {
    record[field] = "";
  }
}

/**
 * @brief Interarrival Time Sequence for Flowset defined in CBSeq
 *
 */
extern "C" void P_iat_cbseq(std::string& option, nlohmann::json& record,
                            const std::string& granularity, const std::string& key,
                            const std::string& field) {
  // option contains flow's start time field name
  // idx contains flow idx
  std::string result = "";
  std::vector<double> start_times;

  for (auto& flow_key : fpnt::get_keys(key, granularity, "flow")) {
    nlohmann::json& cnt = fpnt::d->out["flow"][flow_key];
    // std::cout << "flowkey: " << flow_key << std::endl;
    // std::cout << "option: " << option << std::endl;
    // std::cout << "field: " << cnt[option].get<std::string>() << std::endl;
    if (cnt[option].is_null()) {
      std::cerr << "P_iat_cbseq: Empty arrival time value!" << std::endl;
      exit(1);
    }

    double cnt_start_time = stod(cnt[option].get<std::string>());
    start_times.push_back(cnt_start_time);
  }

  std::vector<double> iats;
  iats.push_back(0);
  if (start_times.size() > 1) {
    for (size_t i = 1; i < start_times.size(); ++i) {
      iats.push_back(start_times[i] - start_times[i - 1]);
    }
  }

  record[field] = vectorToString(iats);
}

/**
 * @brief Return Child count
 *
 */
extern "C" void P_childcount(std::string& option, nlohmann::json& record,
                             const std::string& granularity, const std::string& key,
                             const std::string& field) {
  record[field] = std::to_string(fpnt::d->out_child_keys[granularity][key].size());
}

/**
 * @brief Return Child count if the value is true
 *
 */
extern "C" void P_childcountTrue(std::string& option, nlohmann::json& record,
                                 const std::string& granularity, const std::string& key,
                                 const std::string& field) {
  // option contains out_pkt field name
  // idx contains flow idx
  std::string result = "";
  size_t count = 0;
  std::string child_g = fpnt::d->g_lvs[fpnt::d->g_lv_idx[granularity] - 1];
  for (auto& child_key : fpnt::d->out_child_keys[granularity][key]) {
    nlohmann::json& cnt = fpnt::d->out[child_g][child_key];
    if (cnt[option] == "True") count++;
  }

  record[field] = std::to_string(count);
}

extern "C" void P_childcountFalse(std::string& option, nlohmann::json& record,
                                  const std::string& granularity, const std::string& key,
                                  const std::string& field) {
  // option contains out_pkt field name
  // idx contains flow idx
  std::string result = "";
  size_t count = 0;
  std::string child_g = fpnt::d->g_lvs[fpnt::d->g_lv_idx[granularity] - 1];
  for (auto& child_key : fpnt::d->out_child_keys[granularity][key]) {
    nlohmann::json& cnt = fpnt::d->out[child_g][child_key];
    if (cnt[option] == "False") count++;
  }

  record[field] = std::to_string(count);
}

/**
 * @brief Packet count for any granuality (without packet)
 *
 */
extern "C" void P_pktcount(std::string& option, nlohmann::json& record,
                           const std::string& granularity, const std::string& key,
                           const std::string& field) {
  record[field] = std::to_string(fpnt::get_keys(key, granularity, "pkt").size());
}

/**
 * @brief Packet field aggregation for flowset, without skipping empty fields
 *
 */
extern "C" void P_pf_agg(std::string& option, nlohmann::json& record,
                         const std::string& granularity, const std::string& key,
                         const std::string& field) {
  // option contains out_pkt field name
  // idx contains flow idx
  std::string result = "";
  bool first = true;
  for (auto& pkt_key : fpnt::get_keys(key, granularity, "pkt")) {
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
extern "C" void P_skip_pf_agg(std::string& option, nlohmann::json& record,
                              const std::string& granularity, const std::string& key,
                              const std::string& field) {
  // option contains out_pkt field name
  // idx contains flow idx
  std::string result = "";
  bool first = true;
  for (auto& pkt_key : fpnt::get_keys(key, granularity, "pkt")) {
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
extern "C" void P_fill1(std::string& option, nlohmann::json& record, const std::string& granularity,
                        const std::string& key, const std::string& field) {
  const size_t idx = record["__in_idx"];
  if (record[field] == "") record[field] = fpnt::d->in_pkts[idx][option];
}

/** P_firstcpy4flow: copy the first child's value for flow (typically expecting that the packets in
 * the flow have the same value)
 *
 */
extern "C" void P_firstcpy(std::string& option, nlohmann::json& record,
                           const std::string& granularity, const std::string& key,
                           const std::string& field) {
  std::string child_g = fpnt::d->g_lvs[fpnt::d->g_lv_idx[granularity] - 1];
  auto& first_child_key = fpnt::d->out_child_keys[granularity][key][0];
  record[field] = fpnt::d->out[child_g][first_child_key][option];
}

/** P_fillOpt: fill with option value
 *
 */
extern "C" void P_fillOpt(std::string& option, nlohmann::json& record,
                          const std::string& granularity, const std::string& key,
                          const std::string& field) {
  record[field] = option;
}

/** P_saveKey: save the key corresponding to "option" granularity, of the current record, to the
 * field value Please note this function does not check the availability of such key.
 *
 */
extern "C" void P_saveKey(std::string& option, nlohmann::json& record,
                          const std::string& granularity, const std::string& key,
                          const std::string& field) {
  record[field] = record["__" + option + "_key"];
}

/** P_saveFlowKey: save the corresponding flow record's key, of the current record, to the field
 * value Please note this function does not check the availability of such key.
 *
 */
extern "C" void P_saveFlowKey(std::string& option, nlohmann::json& record,
                              const std::string& granularity, const std::string& key,
                              const std::string& field) {
  record[field] = record["__flow_key"];
}

/** P_saveFlowsetKey: save the corresponding flowset record's key, of the current record, to the
 * field value Please note this function does not check the availability of such key.
 *
 */
extern "C" void P_saveFlowsetKey(std::string& option, nlohmann::json& record,
                                 const std::string& granularity, const std::string& key,
                                 const std::string& field) {
  record[field] = record["__flowset_key"];
}

/** P_savePktKey: save the corresponding pkt's key, of the current record, to the field value
 * Please note this function does not check the availability of such key, but due to the internal
 * design of fpnt, this key must be available.
 *
 */
extern "C" void P_savePktKey(std::string& option, nlohmann::json& record,
                             const std::string& granularity, const std::string& key,
                             const std::string& field) {
  record[field] = record["__pkt_key"];
}

/** P_saveDir: save the corresponding dir, of the current record, to the field value
 * Please note this function does not check the availability of such key, but due to the internal
 * design of fpnt, this key must be available.
 *
 */
extern "C" void P_saveDir(std::string& option, nlohmann::json& record,
                          const std::string& granularity, const std::string& key,
                          const std::string& field) {
  record[field] = record["__dir"];
}

/** P_dir: calculate packet direction (either +1 or -1) based on genKey_flow_default (a stateless
 * flow key generation). That is, the first IP address of the flow key is the smaller one, not the
 * client's IP address. Therefore, When you want to obtain "the TCP style" packet direction
 * sequence, you need to check whether the first packet's direction is +1 or -1. If it is -1, the
 * sequence values should be multiplied by -1.
 */
extern "C" void P_dir(std::string& option, nlohmann::json& record, const std::string& granularity,
                      const std::string& key, const std::string& field) {
  const size_t idx = record["__in_idx"];
  // std::cout << record.dump() << std::endl;
  std::string flow_key = record["__flow_key"].get<std::string>();

  std::string ipsrc = fpnt::d->in_pkts[idx]["_ws.col.def_src"].get<std::string>();

  size_t l;
  if ((l = ipsrc.find(',')) != std::string::npos) {
    ipsrc = ipsrc.substr(0, l);
  }

  if (ipsrc == "") {
    record["__dir"] = "0";  // unexpected value
    return;
  }

  size_t ipsrc_first = flow_key.find(ipsrc);
  size_t ipsrc_last = flow_key.rfind(ipsrc);
  if (ipsrc_first == ipsrc_last) {  // First occurence and last occurence are the same.
                                    // it implies that ipsrc != ipdst
    if (ipsrc_first == 0) {         // this packet's ip.src is firstly located
      record["__dir"] = "+1";
    } else {  // this packet's ip.src is secondly located
      record["__dir"] = "-1";
    }
  } else {  // 'First occurence and last occurence are different' means that this packet is
            // exchanged within the same host.
    std::string dstport = fpnt::d->in_pkts[idx]["tcp.dstport"];
    if (fpnt::d->in_pkts[idx]["udp.dstport"] != "") {
      dstport = fpnt::d->in_pkts[idx]["udp.dstport"];
    }

    if (dstport == "") {      // both tcp and udp has empty dstport
      record["__dir"] = "0";  // unexpected value
      return;
    }

    if (flow_key.length() == flow_key.find(dstport) + dstport.length()) {
      // dstport is located in the second
      record["__dir"] = "+1";
    } else {
      record["__dir"] = "-1";
    }
  }
}

/** P_dir_ipv4: calculate packet direction (either +1 or -1) based on genKey_flow_ipv4 (a stateless
 * flow key generation). That is, the first IP address of the flow key is the smaller one, not the
 * client's IP address. Therefore, When you want to obtain "the TCP style" packet direction
 * sequence, you need to check whether the first packet's direction is +1 or -1. If it is -1, the
 * sequence values should be multiplied by -1.
 */
extern "C" void P_dir_ipv4(std::string& option, nlohmann::json& record,
                           const std::string& granularity, const std::string& key,
                           const std::string& field) {
  const size_t idx = record["__in_idx"];
  // std::cout << record.dump() << std::endl;
  std::string flow_key = record["__flow_key"].get<std::string>();

  if (flow_key.substr(flow_key.length() - 5, 5) == "_IPv6") {
    record["__dir"] = "0";  // unexpected value
    return;
  }

  std::string ipsrc = fpnt::d->in_pkts[idx]["ip.src"];
  if (ipsrc == "") {
    record["__dir"] = "0";  // unexpected value
    return;
  }

  size_t ipsrc_first = flow_key.find(ipsrc);
  size_t ipsrc_last = flow_key.rfind(ipsrc);
  if (ipsrc_first == ipsrc_last) {  // First occurence and last occurence are the same.
                                    // it implies that ipsrc != ipdst
    if (ipsrc_first == 0) {         // this packet's ip.src is firstly located
      record["__dir"] = "+1";
    } else {  // this packet's ip.src is secondly located
      record["__dir"] = "-1";
    }
  } else {  // 'First occurence and last occurence are different' means that this packet is
            // exchanged within the same host.
    std::string dstport = fpnt::d->in_pkts[idx]["tcp.dstport"];
    if (fpnt::d->in_pkts[idx]["udp.dstport"] != "") {
      dstport = fpnt::d->in_pkts[idx]["udp.dstport"];
    }

    if (dstport == "") {      // both tcp and udp has empty dstport
      record["__dir"] = "0";  // unexpected value
      return;
    }

    if (flow_key.length() == flow_key.find(dstport) + dstport.length()) {
      // dstport is located in the second
      record["__dir"] = "+1";
    } else {
      record["__dir"] = "-1";
    }
  }
}