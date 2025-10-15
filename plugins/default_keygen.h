#pragma once
#include <string>
#include <nlohmann/json.hpp>
#include <utility>
#include <string>
#include <csv.hpp>
#include <fpnt/mapper.h>

extern "C" const std::string genKey_pkt_default(const nlohmann::json& pkt, std::string&, std::string&);
extern "C" const std::string genKey_flow_default(const nlohmann::json& pkt, std::string&, std::string&);
extern "C" const std::string genKey_flowset_default(const nlohmann::json& pkt, std::string&, std::string&);

extern "C" const std::string genKey_flow_directional(const nlohmann::json& pkt, std::string& granularity, std::string& key);

extern "C" const std::string genKey_pkt_cbr(const nlohmann::json& pkt, std::string&, std::string&);
extern "C" const std::string genKey_protocol_default(const nlohmann::json& pkt, std::string& granularity, std::string& key);