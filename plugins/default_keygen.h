#pragma once
#include <string>
#include <nlohmann/json.hpp>
#include <utility>
#include <string>
#include <csv.hpp>
#include <fpnt/mapper.h>

extern "C" const std::string genKey_pkt_default(const nlohmann::json& pkt, fpnt::Mapper& map);
extern "C" const std::string genKey_flow_default(const nlohmann::json& pkt, fpnt::Mapper& map);
extern "C" const std::string genKey_flowset_default(const nlohmann::json& pkt, fpnt::Mapper& map);