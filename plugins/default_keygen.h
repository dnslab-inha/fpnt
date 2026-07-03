#pragma once
#include <fpnt/key_generator.h>
#include <fpnt/mapper.h>

#include <csv.hpp>
#include <nlohmann/json.hpp>

extern "C" fpnt::KeyGenerator* create_genKey_pkt_default();
extern "C" fpnt::KeyGenerator* create_genKey_flow_default();
extern "C" fpnt::KeyGenerator* create_genKey_flowset_default();
extern "C" fpnt::KeyGenerator* create_genKey_flow_directional();
extern "C" fpnt::KeyGenerator* create_genKey_flow_default_5tuple();
extern "C" fpnt::KeyGenerator* create_genKey_flow_directional_default_5tuple();

extern "C" fpnt::KeyGenerator* create_genKey_flow_ipv4();
extern "C" fpnt::KeyGenerator* create_genKey_flowset_ipv4();
extern "C" fpnt::KeyGenerator* create_genKey_flow_directional_ipv4();
extern "C" fpnt::KeyGenerator* create_genKey_flow_directional_ipv4_5tuple();

extern "C" fpnt::KeyGenerator* create_genKey_pkt_cbr();
extern "C" fpnt::KeyGenerator* create_genKey_protocol_default();
