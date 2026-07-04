#include "default_keygen.h"

#include <arpa/inet.h>
#include <fmt/core.h>

#include <charconv>
#include <cstring>
#include <string>
#include <string_view>

static inline std::string safe_get_string(const nlohmann::json& pkt, const std::string& key) {
  if (pkt.contains(key)) {
    if (pkt[key].is_string()) return pkt[key].get<std::string>();
    if (pkt[key].is_number()) return pkt[key].dump();
  }
  return "";
}

namespace {
  inline int parse_port(std::string s) {
    int port = 0;
    if (!s.empty()) {
      std::from_chars(s.data(), s.data() + s.size(), port);
    }
    return port;
  }
}  // namespace

/** @brief Default key generator for Packet records;
 * just use its record creation order starting from 0
 *
 */
class GenKey_pkt_default : public fpnt::KeyGenerator {
public:
  GenKey_pkt_default() : fpnt::KeyGenerator({"idx"}) {}
  nlohmann::json genKey(const fpnt::KeyGenContext& ctx) override {
    const auto& pkt = ctx.pkt;
    [[maybe_unused]] auto& granularity = ctx.granularity;
    [[maybe_unused]] auto file_idx = ctx.file_idx;

    nlohmann::json key_data;
    key_data["__" + granularity + "_key"] = std::to_string(pkt["idx"].get<size_t>());
    return key_data;
  }
};
extern "C" fpnt::KeyGenerator* create_genKey_pkt_default() { return new GenKey_pkt_default(); }

/** @brief Default key generator for "bidirectional" Flow records assuming only TCP/IP, UDP/IP
 * datagrams are available for efficient generation; use "4 tuple" fields (_ws.col.def_src,
 * _ws.col.def_dst, tcp.srcport or udp.srcport, tcp.dstport or udp.dstport); suitable for
 * encrypted traffic analysis such as TLS or QUIC; note that the host with smaller port number
 * is appeared first (to identify well-known service port quickly) and if the port numbers are
 * the same, the host with smaller IP address is appeared first.
 */
class GenKey_flow_default : public fpnt::KeyGenerator {
public:
  GenKey_flow_default()
      : fpnt::KeyGenerator({"idx", "tcp.srcport", "_ws.col.def_dst", "udp.srcport", "udp.dstport",
                            "_ws.col.def_src", "tcp.dstport"}) {}
  nlohmann::json genKey(const fpnt::KeyGenContext& ctx) override {
    const auto& pkt = ctx.pkt;
    [[maybe_unused]] auto& granularity = ctx.granularity;
    [[maybe_unused]] auto file_idx = ctx.file_idx;

    std::string cur_key;
    nlohmann::json key_data;

    std::string cur_srcport;
    std::string cur_dstport;
    if (pkt.contains("tcp.srcport") && !pkt["tcp.srcport"].is_null()
        && !safe_get_string(pkt, "tcp.srcport").empty()) {
      cur_srcport = safe_get_string(pkt, "tcp.srcport");
      cur_dstport = safe_get_string(pkt, "tcp.dstport");
    } else if (pkt.contains("udp.srcport") && !pkt["udp.srcport"].is_null()
               && !safe_get_string(pkt, "udp.srcport").empty()) {
      cur_srcport = safe_get_string(pkt, "udp.srcport");
      cur_dstport = safe_get_string(pkt, "udp.dstport");
    } else {
      cur_srcport = "0";
      cur_dstport = "0";
    }

    std::string cur_src = safe_get_string(pkt, "_ws.col.def_src");
    std::string cur_dst = safe_get_string(pkt, "_ws.col.def_dst");

    size_t l;
    if ((l = cur_src.find(',')) != std::string::npos) {
      cur_src = cur_src.substr(0, l);
    }
    if ((l = cur_dst.find(',')) != std::string::npos) {
      cur_dst = cur_dst.substr(0, l);
    }

    // flow key generation policy:
    // We assume that smaller port number address is the server;
    // if the port number address is the same (found in many UDP cases),
    //    we assume that the smaller IP address is the server
    // We use the client-first, server-second pair
    if (cur_src.empty() || cur_dst.empty()) {
      return key_data;
    }

    int keycomp = parse_port(cur_srcport) - parse_port(cur_dstport);
    if (keycomp == 0)  // the port number same case
    {
      bool src_greater_equal = false;
      if (cur_src.find(':') != std::string::npos) {  // IPv6
        struct in6_addr src_n, dst_n;
        if (inet_pton(AF_INET6, std::string(cur_src).c_str(), &src_n) != 1
            || inet_pton(AF_INET6, std::string(cur_dst).c_str(), &dst_n) != 1) {
          std::cerr << "Invalid IPv6 address" << std::endl;
          std::cerr << pkt["idx"].get<size_t>() << "," << safe_get_string(pkt, "_ws.col.def_src")
                    << "," << safe_get_string(pkt, "_ws.col.def_dst") << std::endl;
          exit(EXIT_FAILURE);
        }
        if (memcmp(&src_n, &dst_n, sizeof(src_n)) >= 0) src_greater_equal = true;
      } else {  // IPv4
        struct in_addr src_n, dst_n;
        if (inet_pton(AF_INET, std::string(cur_src).c_str(), &src_n) != 1
            || inet_pton(AF_INET, std::string(cur_dst).c_str(), &dst_n) != 1) {
          std::cerr << "Invalid IPv4 address" << std::endl;
          std::cerr << pkt["idx"].get<size_t>() << "," << safe_get_string(pkt, "_ws.col.def_src")
                    << "," << safe_get_string(pkt, "_ws.col.def_dst") << std::endl;
          exit(EXIT_FAILURE);
        }
        // Compare in network byte order (Big Endian)
        if (memcmp(&src_n, &dst_n, sizeof(src_n)) >= 0) src_greater_equal = true;
      }

      if (src_greater_equal) {  // dst_n is the server
        cur_key = fmt::format("{0}:{1},{2}:{3}", cur_src, cur_srcport, cur_dst, cur_dstport);
        key_data["__dir"] = "+1";
      } else {  // dst_n is the client
        cur_key = fmt::format("{2}:{3},{0}:{1}", cur_src, cur_srcport, cur_dst, cur_dstport);
        key_data["__dir"] = "-1";
      }
    } else if (keycomp > 0) {  // srcport > dstport                   dstport is the server
      cur_key = fmt::format("{0}:{1},{2}:{3}", cur_src, cur_srcport, cur_dst, cur_dstport);
      key_data["__dir"] = "+1";
    } else {  // srcport < dstport                   dstport is the client
      cur_key = fmt::format("{2}:{3},{0}:{1}", cur_src, cur_srcport, cur_dst, cur_dstport);
      key_data["__dir"] = "-1";
    }

    key_data["__" + granularity + "_key"] = cur_key;
    return key_data;
  }
};
extern "C" fpnt::KeyGenerator* create_genKey_flow_default() { return new GenKey_flow_default(); }

/** @brief Default key generator for "bidirectional" Flow records assuming only TCP/IP, UDP/IP
 * datagrams are available for efficient generation; use the standard "5 tuple" fields
 * (_ws.col.def_src, _ws.col.def_dst, tcp.srcport or udp.srcport, tcp.dstport or udp.dstport,
 * protocol); suitable for encrypted traffic analysis for conventional TCP/IP protocol; note that
 * the host with smaller port number is appeared first (to identify well-known service port quickly)
 * and if the port numbers are the same, the host with smaller IP address is appeared first. key
 * string is "srcIP:srcPort,dstIP:dstPort/protocol".
 *
 */
class GenKey_flow_default_5tuple : public fpnt::KeyGenerator {
public:
  GenKey_flow_default_5tuple()
      : fpnt::KeyGenerator({"idx", "ipv6.nxt", "tcp.srcport", "_ws.col.def_dst", "ip.proto",
                            "udp.srcport", "udp.dstport", "_ws.col.def_src", "tcp.dstport"}) {}
  nlohmann::json genKey(const fpnt::KeyGenContext& ctx) override {
    const auto& pkt = ctx.pkt;
    [[maybe_unused]] auto& granularity = ctx.granularity;
    [[maybe_unused]] auto file_idx = ctx.file_idx;

    std::string cur_key;
    nlohmann::json key_data;

    std::string cur_srcport;
    std::string cur_dstport;
    if (pkt.contains("tcp.srcport") && !pkt["tcp.srcport"].is_null()
        && !safe_get_string(pkt, "tcp.srcport").empty()) {
      cur_srcport = safe_get_string(pkt, "tcp.srcport");
      cur_dstport = safe_get_string(pkt, "tcp.dstport");
    } else if (pkt.contains("udp.srcport") && !pkt["udp.srcport"].is_null()
               && !safe_get_string(pkt, "udp.srcport").empty()) {
      cur_srcport = safe_get_string(pkt, "udp.srcport");
      cur_dstport = safe_get_string(pkt, "udp.dstport");
    } else {
      cur_srcport = "0";
      cur_dstport = "0";
    }

    std::string cur_src = safe_get_string(pkt, "_ws.col.def_src");
    std::string cur_dst = safe_get_string(pkt, "_ws.col.def_dst");

    size_t l;
    if ((l = cur_src.find(',')) != std::string::npos) {
      cur_src = cur_src.substr(0, l);
    }
    if ((l = cur_dst.find(',')) != std::string::npos) {
      cur_dst = cur_dst.substr(0, l);
    }

    // flow key generation policy:
    // We assume that smaller port number address is the server;
    // if the port number address is the same (found in many UDP cases),
    //    we assume that the smaller IP address is the server
    // We use the client-first, server-second pair

    std::string ip_proto;
    if (pkt.contains("ip.proto") && !pkt["ip.proto"].is_null()) {
      ip_proto = safe_get_string(pkt, "ip.proto");
    }
    if (ip_proto.empty()) {
      if (pkt.contains("ipv6.nxt") && !pkt["ipv6.nxt"].is_null()) {
        ip_proto = safe_get_string(pkt, "ipv6.nxt");
      }
    }

    if ((l = ip_proto.find(',')) != std::string::npos) {
      ip_proto = ip_proto.substr(0, l);
    }
    if (cur_src.empty() || cur_dst.empty()) {
      return key_data;
    }

    int keycomp = parse_port(cur_srcport) - parse_port(cur_dstport);
    if (keycomp == 0)  // the port number same case
    {
      bool src_greater_equal = false;
      if (cur_src.find(':') != std::string::npos) {  // IPv6
        struct in6_addr src_n, dst_n;
        if (inet_pton(AF_INET6, std::string(cur_src).c_str(), &src_n) != 1
            || inet_pton(AF_INET6, std::string(cur_dst).c_str(), &dst_n) != 1) {
          std::cerr << "Invalid IPv6 address" << std::endl;
          std::cerr << pkt["idx"].get<size_t>() << "," << safe_get_string(pkt, "_ws.col.def_src")
                    << "," << safe_get_string(pkt, "_ws.col.def_dst") << std::endl;
          exit(EXIT_FAILURE);
        }
        if (memcmp(&src_n, &dst_n, sizeof(src_n)) >= 0) src_greater_equal = true;
      } else {  // IPv4
        struct in_addr src_n, dst_n;
        if (inet_pton(AF_INET, std::string(cur_src).c_str(), &src_n) != 1
            || inet_pton(AF_INET, std::string(cur_dst).c_str(), &dst_n) != 1) {
          std::cerr << "Invalid IPv4 address" << std::endl;
          std::cerr << pkt["idx"].get<size_t>() << "," << safe_get_string(pkt, "_ws.col.def_src")
                    << "," << safe_get_string(pkt, "_ws.col.def_dst") << std::endl;
          exit(EXIT_FAILURE);
        }
        // Compare in network byte order (Big Endian)
        if (memcmp(&src_n, &dst_n, sizeof(src_n)) >= 0) src_greater_equal = true;
      }

      if (src_greater_equal) {  // dst_n is the server
        cur_key = fmt::format("{0}:{1},{2}:{3}/{4}", cur_src, cur_srcport, cur_dst, cur_dstport,
                              ip_proto);
        key_data["__dir"] = "+1";
      } else {  // dst_n is the client
        cur_key = fmt::format("{2}:{3},{0}:{1}/{4}", cur_src, cur_srcport, cur_dst, cur_dstport,
                              ip_proto);
        key_data["__dir"] = "-1";
      }
    } else if (keycomp > 0) {  // srcport > dstport                   dstport is the server
      cur_key = fmt::format("{0}:{1},{2}:{3}/{4}", cur_src, cur_srcport, cur_dst, cur_dstport,
                            ip_proto);
      key_data["__dir"] = "+1";
    } else {  // srcport < dstport                   dstport is the client
      cur_key = fmt::format("{2}:{3},{0}:{1}/{4}", cur_src, cur_srcport, cur_dst, cur_dstport,
                            ip_proto);
      key_data["__dir"] = "-1";
    }

    key_data["__" + granularity + "_key"] = cur_key;
    return key_data;
  }
};
extern "C" fpnt::KeyGenerator* create_genKey_flow_default_5tuple() {
  return new GenKey_flow_default_5tuple();
}

/** @brief A key generator for "bidirectional" Flow records assuming only TCP/IPv4, UDP/IPv4
 * datagrams are available for efficient generation; use 4 tuple fields
 * (ip.src, ip.dst, tcp.srcport or udp.srcport, tcp.dstport or udp.dstport)
 * suitable for IPv4 traffic analysis only; non-IPv4 packets will have flow key string
 * "{file_idx}_NonIPv4". note that the host with smaller port number is appeared first (to identify
 * well-known service port quickly) and if the port numbers are the same, the host with smaller IP
 * address is appeared first.
 *
 */
class GenKey_flow_ipv4 : public fpnt::KeyGenerator {
public:
  GenKey_flow_ipv4()
      : fpnt::KeyGenerator(
            {"ip.src", "tcp.srcport", "udp.srcport", "udp.dstport", "ip.dst", "tcp.dstport"}) {}
  nlohmann::json genKey(const fpnt::KeyGenContext& ctx) override {
    const auto& pkt = ctx.pkt;
    [[maybe_unused]] auto& granularity = ctx.granularity;
    [[maybe_unused]] auto file_idx = ctx.file_idx;

    std::string cur_key;
    nlohmann::json key_data;

    std::string cur_srcport;
    std::string cur_dstport;
    if (pkt.contains("tcp.srcport") && !pkt["tcp.srcport"].is_null()
        && !safe_get_string(pkt, "tcp.srcport").empty()) {
      cur_srcport = safe_get_string(pkt, "tcp.srcport");
      cur_dstport = safe_get_string(pkt, "tcp.dstport");
    } else {
      if (pkt["udp.srcport"].is_null() || pkt["udp.dstport"].is_null()) {
        std::cerr << "getPktKey: the corresponding input json does not collect udp.srcport and/or "
                     "udp.dstport."
                  << std::endl;
        std::cerr
            << "getPktKey: When tshark is used and UDP flows are needless, tshark must filter "
               "off UDP packets."
            << std::endl;
        exit(EXIT_FAILURE);
      }
      if (!safe_get_string(pkt, "udp.srcport").empty()) {
        cur_srcport = safe_get_string(pkt, "udp.srcport");
        cur_dstport = safe_get_string(pkt, "udp.dstport");
      } else {
        cur_srcport = "0";
        cur_dstport = "0";
      }
    }

    std::string cur_src = safe_get_string(pkt, "ip.src");
    std::string cur_dst = safe_get_string(pkt, "ip.dst");

    // if IPv6 address is given... ;<
    if (cur_src.empty() && cur_dst.empty()) {
      key_data["__" + granularity + "_key"] = std::to_string(file_idx) + "_NonIPv4";
      return key_data;  // the only location to use dispatcher's file_idx
    }

    size_t l;
    if ((l = cur_src.find(',')) != std::string::npos) {
      cur_src = cur_src.substr(0, l);
    }
    if ((l = cur_dst.find(',')) != std::string::npos) {
      cur_dst = cur_dst.substr(0, l);
    }

    // flow key generation policy:
    // We assume that smaller port number address is the server;
    // if the port number address is the same (found in many UDP cases),
    //    we assume that the smaller IP address is the server
    // We use the client-first, server-second pair
    if (cur_src.empty() || cur_dst.empty()) {
      return key_data;
    }

    int keycomp = parse_port(cur_srcport) - parse_port(cur_dstport);
    if (keycomp == 0)  // the port number same case
    {
      struct in_addr src_n, dst_n;
      if (inet_aton(std::string(cur_src).c_str(), &src_n) == 0
          || inet_aton(std::string(cur_dst).c_str(), &dst_n) == 0) {
        std::cerr << "Invalid address" << std::endl;
        exit(EXIT_FAILURE);
      }
      if (src_n.s_addr >= dst_n.s_addr) {  // dst_n is the server
        cur_key = fmt::format("{0}:{1},{2}:{3}", cur_src, cur_srcport, cur_dst, cur_dstport);
        key_data["__dir"] = "+1";
      } else {  // dst_n is the client
        cur_key = fmt::format("{2}:{3},{0}:{1}", cur_src, cur_srcport, cur_dst, cur_dstport);
        key_data["__dir"] = "-1";
      }
    } else if (keycomp > 0) {  // srcport > dstport                   dstport is the server
      cur_key = fmt::format("{0}:{1},{2}:{3}", cur_src, cur_srcport, cur_dst, cur_dstport);
      key_data["__dir"] = "+1";
    } else {  // srcport < dstport                   dstport is the client
      cur_key = fmt::format("{2}:{3},{0}:{1}", cur_src, cur_srcport, cur_dst, cur_dstport);
      key_data["__dir"] = "-1";
    }
    key_data["__" + granularity + "_key"] = cur_key;
    return key_data;
  }
};
extern "C" fpnt::KeyGenerator* create_genKey_flow_ipv4() { return new GenKey_flow_ipv4(); }

/** @brief A key generator for "bidirectional" Flow records assuming only IPv4 datagrams are
 * available for efficient generation; use 5 tuple fields
 */
class GenKey_flow_ipv4_5tuple : public fpnt::KeyGenerator {
public:
  GenKey_flow_ipv4_5tuple()
      : fpnt::KeyGenerator({"ip.src", "tcp.srcport", "udp.srcport", "udp.dstport", "ip.dst",
                            "tcp.dstport", "ip.proto"}) {}
  nlohmann::json genKey(const fpnt::KeyGenContext& ctx) override {
    const auto& pkt = ctx.pkt;
    [[maybe_unused]] auto& granularity = ctx.granularity;
    [[maybe_unused]] auto file_idx = ctx.file_idx;

    std::string cur_key;
    nlohmann::json key_data;

    std::string cur_srcport;
    std::string cur_dstport;
    if (pkt.contains("tcp.srcport") && !pkt["tcp.srcport"].is_null()
        && !safe_get_string(pkt, "tcp.srcport").empty()) {
      cur_srcport = safe_get_string(pkt, "tcp.srcport");
      cur_dstport = safe_get_string(pkt, "tcp.dstport");
    } else {
      if (pkt["udp.srcport"].is_null() || pkt["udp.dstport"].is_null()) {
        std::cerr << "getPktKey: the corresponding input json does not collect udp.srcport and/or "
                     "udp.dstport."
                  << std::endl;
        std::cerr
            << "getPktKey: When tshark is used and UDP flows are needless, tshark must filter "
               "off UDP packets."
            << std::endl;
        exit(EXIT_FAILURE);
      }
      if (!safe_get_string(pkt, "udp.srcport").empty()) {
        cur_srcport = safe_get_string(pkt, "udp.srcport");
        cur_dstport = safe_get_string(pkt, "udp.dstport");
      } else {
        cur_srcport = "0";
        cur_dstport = "0";
      }
    }

    std::string cur_src = safe_get_string(pkt, "ip.src");
    std::string cur_dst = safe_get_string(pkt, "ip.dst");

    // if IPv6 address is given... ;<
    if (cur_src.empty() && cur_dst.empty()) {
      key_data["__" + granularity + "_key"] = std::to_string(file_idx) + "_NonIPv4";
      return key_data;  // the only location to use dispatcher's file_idx
    }

    size_t l;
    if ((l = cur_src.find(',')) != std::string::npos) {
      cur_src = cur_src.substr(0, l);
    }
    if ((l = cur_dst.find(',')) != std::string::npos) {
      cur_dst = cur_dst.substr(0, l);
    }

    std::string ip_proto;
    if (pkt.contains("ip.proto") && !pkt["ip.proto"].is_null()) {
      ip_proto = safe_get_string(pkt, "ip.proto");
    }

    if ((l = ip_proto.find(',')) != std::string::npos) {
      ip_proto = ip_proto.substr(0, l);
    }

    // flow key generation policy:
    // We assume that smaller port number address is the server;
    // if the port number address is the same (found in many UDP cases),
    //    we assume that the smaller IP address is the server
    // We use the client-first, server-second pair
    if (cur_src.empty() || cur_dst.empty()) {
      return key_data;
    }

    int keycomp = parse_port(cur_srcport) - parse_port(cur_dstport);
    if (keycomp == 0)  // the port number same case
    {
      struct in_addr src_n, dst_n;
      if (inet_aton(std::string(cur_src).c_str(), &src_n) == 0
          || inet_aton(std::string(cur_dst).c_str(), &dst_n) == 0) {
        std::cerr << "Invalid address" << std::endl;
        exit(EXIT_FAILURE);
      }
      if (src_n.s_addr >= dst_n.s_addr) {  // dst_n is the server
        cur_key = fmt::format("{0}:{1},{2}:{3}/{4}", cur_src, cur_srcport, cur_dst, cur_dstport,
                              ip_proto);
        key_data["__dir"] = "+1";
      } else {  // dst_n is the client
        cur_key = fmt::format("{2}:{3},{0}:{1}/{4}", cur_src, cur_srcport, cur_dst, cur_dstport,
                              ip_proto);
        key_data["__dir"] = "-1";
      }
    } else if (keycomp > 0) {  // srcport > dstport                   dstport is the server
      cur_key = fmt::format("{0}:{1},{2}:{3}/{4}", cur_src, cur_srcport, cur_dst, cur_dstport,
                            ip_proto);
      key_data["__dir"] = "+1";
    } else {  // srcport < dstport                   dstport is the client
      cur_key = fmt::format("{2}:{3},{0}:{1}/{4}", cur_src, cur_srcport, cur_dst, cur_dstport,
                            ip_proto);
      key_data["__dir"] = "-1";
    }
    key_data["__" + granularity + "_key"] = cur_key;
    return key_data;
  }
};
extern "C" fpnt::KeyGenerator* create_genKey_flow_ipv4_5tuple() {
  return new GenKey_flow_ipv4_5tuple();
}

/** @brief Default key generator for "directional" Flow records assuming only TCP/IP, UDP/IP
 * datagrams are available for efficient generation; use "4 tuple" fields (_ws.col.def_src,
 * _ws.col.def_dst, tcp.srcport or udp.srcport, tcp.dstport or udp.dstport); suitable for
 * encrypted traffic analysis such as TLS or QUIC; key string is "srcIP:srcPort,dstIP:dstPort".
 */
class GenKey_flow_directional_default : public fpnt::KeyGenerator {
public:
  GenKey_flow_directional_default()
      : fpnt::KeyGenerator({"tcp.srcport", "_ws.col.def_dst", "udp.srcport", "udp.dstport",
                            "_ws.col.def_src", "tcp.dstport"}) {}
  nlohmann::json genKey(const fpnt::KeyGenContext& ctx) override {
    const auto& pkt = ctx.pkt;
    [[maybe_unused]] auto& granularity = ctx.granularity;
    [[maybe_unused]] auto file_idx = ctx.file_idx;

    std::string cur_key;
    nlohmann::json key_data;

    std::string cur_srcport;
    std::string cur_dstport;
    if (pkt.contains("tcp.srcport") && !pkt["tcp.srcport"].is_null()
        && !safe_get_string(pkt, "tcp.srcport").empty()) {
      cur_srcport = safe_get_string(pkt, "tcp.srcport");
      cur_dstport = safe_get_string(pkt, "tcp.dstport");
    } else if (pkt.contains("udp.srcport") && !pkt["udp.srcport"].is_null()
               && !safe_get_string(pkt, "udp.srcport").empty()) {
      cur_srcport = safe_get_string(pkt, "udp.srcport");
      cur_dstport = safe_get_string(pkt, "udp.dstport");
    } else {
      cur_srcport = "0";
      cur_dstport = "0";
    }

    std::string cur_src = safe_get_string(pkt, "_ws.col.def_src");
    std::string cur_dst = safe_get_string(pkt, "_ws.col.def_dst");

    // fix a bug in tshark
    // sometimes, ip.src or ip.dst can have unexpected comma due to a bug in tshark. we will use the
    // first part of the address

    size_t l;
    if ((l = cur_src.find(',')) != std::string::npos) {
      cur_src = cur_src.substr(0, l);
    }
    if ((l = cur_dst.find(',')) != std::string::npos) {
      cur_dst = cur_dst.substr(0, l);
    }

    cur_key = fmt::format("{0}:{1},{2}:{3}", cur_src, cur_srcport, cur_dst, cur_dstport);
    key_data["__dir"] = "+1";

    key_data["__" + granularity + "_key"] = cur_key;
    return key_data;
  }
};
extern "C" fpnt::KeyGenerator* create_genKey_flow_directional_default() {
  return new GenKey_flow_directional_default();
}

/** @brief A key generator for "directional" Flow records assuming only TCP/IPv4, UDP/IPv4 datagrams
 * are available for efficient generation; use 4 tuple fields (ip.src,
 * ip.dst, tcp.srcport or udp.srcport, tcp.dstport or udp.dstport); suitable for
 * IPv4 traffic analysis only; key string is "srcIP:srcPort,dstIP:dstPort".
 * non-IPv4 packets will have flow key string "{file_idx}_NonIPv4".
 */
class GenKey_flow_directional_ipv4 : public fpnt::KeyGenerator {
public:
  GenKey_flow_directional_ipv4()
      : fpnt::KeyGenerator(
            {"ip.src", "tcp.srcport", "udp.srcport", "udp.dstport", "ip.dst", "tcp.dstport"}) {}
  nlohmann::json genKey(const fpnt::KeyGenContext& ctx) override {
    const auto& pkt = ctx.pkt;
    [[maybe_unused]] auto& granularity = ctx.granularity;
    [[maybe_unused]] auto file_idx = ctx.file_idx;

    std::string cur_key;
    nlohmann::json key_data;

    std::string cur_srcport;
    std::string cur_dstport;
    if (pkt.contains("tcp.srcport") && !pkt["tcp.srcport"].is_null()
        && !safe_get_string(pkt, "tcp.srcport").empty()) {
      cur_srcport = safe_get_string(pkt, "tcp.srcport");
      cur_dstport = safe_get_string(pkt, "tcp.dstport");
    } else {
      if (pkt["udp.srcport"].is_null() || pkt["udp.dstport"].is_null()) {
        std::cerr << "getPktKey: the corresponding input json does not collect udp.srcport and/or "
                     "udp.dstport."
                  << std::endl;
        std::cerr
            << "getPktKey: When tshark is used and UDP flows are needless, tshark must filter "
               "off UDP packets."
            << std::endl;
        exit(EXIT_FAILURE);
      }
      if (!safe_get_string(pkt, "udp.srcport").empty()) {
        cur_srcport = safe_get_string(pkt, "udp.srcport");
        cur_dstport = safe_get_string(pkt, "udp.dstport");
      } else {
        cur_srcport = "0";
        cur_dstport = "0";
      }
    }

    std::string cur_src = safe_get_string(pkt, "ip.src");
    std::string cur_dst = safe_get_string(pkt, "ip.dst");

    // if IPv6 address is given... ;<
    if (cur_src.empty() && cur_dst.empty()) {
      key_data["__" + granularity + "_key"] = std::to_string(file_idx) + "_NonIPv4";
      return key_data;  // the only location to use dispatcher's file_idx
    }

    size_t l;
    if ((l = cur_src.find(',')) != std::string::npos) {
      cur_src = cur_src.substr(0, l);
    }
    if ((l = cur_dst.find(',')) != std::string::npos) {
      cur_dst = cur_dst.substr(0, l);
    }

    cur_key = fmt::format("{0}:{1},{2}:{3}", cur_src, cur_srcport, cur_dst, cur_dstport);
    key_data["__dir"] = "+1";

    key_data["__" + granularity + "_key"] = cur_key;
    return key_data;
  }
};
extern "C" fpnt::KeyGenerator* create_genKey_flow_directional_ipv4() {
  return new GenKey_flow_directional_ipv4();
}

/** @brief Default key generator for "directional" Flow records assuming only TCP/IP, UDP/IP
 * datagrams are available for efficient generation; the standard "5 tuple" fields
 * (_ws.col.def_src, _ws.col.def_dst, tcp.srcport or udp.srcport, tcp.dstport or udp.dstport,
 * protocol); suitable for encrypted traffic analysis for conventional TCP/IP protocol; key string
 * is "srcIP:srcPort,dstIP:dstPort/protocol".
 */
class GenKey_flow_directional_default_5tuple : public fpnt::KeyGenerator {
public:
  GenKey_flow_directional_default_5tuple()
      : fpnt::KeyGenerator({"ipv6.nxt", "tcp.srcport", "_ws.col.def_dst", "ip.proto", "udp.srcport",
                            "udp.dstport", "_ws.col.def_src", "tcp.dstport"}) {}
  nlohmann::json genKey(const fpnt::KeyGenContext& ctx) override {
    const auto& pkt = ctx.pkt;
    [[maybe_unused]] auto& granularity = ctx.granularity;
    [[maybe_unused]] auto file_idx = ctx.file_idx;

    std::string cur_key;
    nlohmann::json key_data;

    std::string cur_srcport;
    std::string cur_dstport;
    if (pkt.contains("tcp.srcport") && !pkt["tcp.srcport"].is_null()
        && !safe_get_string(pkt, "tcp.srcport").empty()) {
      cur_srcport = safe_get_string(pkt, "tcp.srcport");
      cur_dstport = safe_get_string(pkt, "tcp.dstport");
    } else if (pkt.contains("udp.srcport") && !pkt["udp.srcport"].is_null()
               && !safe_get_string(pkt, "udp.srcport").empty()) {
      cur_srcport = safe_get_string(pkt, "udp.srcport");
      cur_dstport = safe_get_string(pkt, "udp.dstport");
    } else {
      cur_srcport = "0";
      cur_dstport = "0";
    }

    std::string cur_src = safe_get_string(pkt, "_ws.col.def_src");
    std::string cur_dst = safe_get_string(pkt, "_ws.col.def_dst");

    // fix a bug in tshark
    // sometimes, ip.src or ip.dst can have unexpected comma due to a bug in tshark. we will use the
    // first part of the address

    size_t l;
    if ((l = cur_src.find(',')) != std::string::npos) {
      cur_src = cur_src.substr(0, l);
    }
    if ((l = cur_dst.find(',')) != std::string::npos) {
      cur_dst = cur_dst.substr(0, l);
    }

    std::string ip_proto = safe_get_string(pkt, "ip.proto");

    if (ip_proto.empty()) {
      ip_proto = safe_get_string(pkt, "ipv6.nxt");
    }

    if ((l = ip_proto.find(',')) != std::string::npos) {
      ip_proto = ip_proto.substr(0, l);
    }

    cur_key
        = fmt::format("{0}:{1},{2}:{3}/{4}", cur_src, cur_srcport, cur_dst, cur_dstport, ip_proto);
    key_data["__dir"] = "+1";

    key_data["__" + granularity + "_key"] = cur_key;
    return key_data;
  }
};
extern "C" fpnt::KeyGenerator* create_genKey_flow_directional_default_5tuple() {
  return new GenKey_flow_directional_default_5tuple();
}

/** @brief A key generator for "directional" Flow records assuming only TCP/IPv4, UDP/IPv4 datagrams
 * are available for efficient generation; use 4 tuple fields (ip.src,
 * ip.dst, tcp.srcport or udp.srcport, tcp.dstport or udp.dstport); suitable for
 * IPv4 traffic analysis only; key string is "srcIP:srcPort,dstIP:dstPort".
 * non-IPv4 packets will have flow key string "{file_idx}_NonIPv4".
 */
class GenKey_flow_directional_ipv4_5tuple : public fpnt::KeyGenerator {
public:
  GenKey_flow_directional_ipv4_5tuple()
      : fpnt::KeyGenerator({"ip.src", "tcp.srcport", "ipv6.nxt", "ip.proto", "udp.srcport",
                            "udp.dstport", "ip.dst", "tcp.dstport"}) {}
  nlohmann::json genKey(const fpnt::KeyGenContext& ctx) override {
    const auto& pkt = ctx.pkt;
    [[maybe_unused]] auto& granularity = ctx.granularity;
    [[maybe_unused]] auto file_idx = ctx.file_idx;

    std::string cur_key;
    nlohmann::json key_data;

    std::string cur_srcport;
    std::string cur_dstport;
    if (pkt.contains("tcp.srcport") && !pkt["tcp.srcport"].is_null()
        && !safe_get_string(pkt, "tcp.srcport").empty()) {
      cur_srcport = safe_get_string(pkt, "tcp.srcport");
      cur_dstport = safe_get_string(pkt, "tcp.dstport");
    } else {
      if (pkt["udp.srcport"].is_null() || pkt["udp.dstport"].is_null()) {
        std::cerr << "getPktKey: the corresponding input json does not collect udp.srcport and/or "
                     "udp.dstport."
                  << std::endl;
        std::cerr
            << "getPktKey: When tshark is used and UDP flows are needless, tshark must filter "
               "off UDP packets."
            << std::endl;
        exit(EXIT_FAILURE);
      }
      if (!safe_get_string(pkt, "udp.srcport").empty()) {
        cur_srcport = safe_get_string(pkt, "udp.srcport");
        cur_dstport = safe_get_string(pkt, "udp.dstport");
      } else {
        cur_srcport = "0";
        cur_dstport = "0";
      }
    }

    std::string cur_src = safe_get_string(pkt, "ip.src");
    std::string cur_dst = safe_get_string(pkt, "ip.dst");

    // if IPv6 address is given... ;<
    if (cur_src.empty() && cur_dst.empty()) {
      key_data["__" + granularity + "_key"] = std::to_string(file_idx) + "_NonIPv4";
      return key_data;  // the only location to use dispatcher's file_idx
    }

    size_t l;
    if ((l = cur_src.find(',')) != std::string::npos) {
      cur_src = cur_src.substr(0, l);
    }
    if ((l = cur_dst.find(',')) != std::string::npos) {
      cur_dst = cur_dst.substr(0, l);
    }

    std::string ip_proto = safe_get_string(pkt, "ip.proto");

    if (ip_proto.empty()) {
      ip_proto = safe_get_string(pkt, "ipv6.nxt");
    }

    if ((l = ip_proto.find(',')) != std::string::npos) {
      ip_proto = ip_proto.substr(0, l);
    }

    cur_key
        = fmt::format("{0}:{1},{2}:{3}/{4}", cur_src, cur_srcport, cur_dst, cur_dstport, ip_proto);
    key_data["__dir"] = "+1";

    key_data["__" + granularity + "_key"] = cur_key;
    return key_data;
  }
};
extern "C" fpnt::KeyGenerator* create_genKey_flow_directional_ipv4_5tuple() {
  return new GenKey_flow_directional_ipv4_5tuple();
}

/** @brief Default key generator for "bidirectional" Flow records assuming only IPv4 datagrams are
 * available for efficient generation; use _ws.col.def_src and _ws.col.def_dst fields; suitable for
 * encrypted traffic analysis such as TLS or QUIC; note that the host with smaller IP address is
 * appeared first
 *
 */
class GenKey_flowset_default : public fpnt::KeyGenerator {
public:
  GenKey_flowset_default() : fpnt::KeyGenerator({"_ws.col.def_src", "_ws.col.def_dst"}) {}
  nlohmann::json genKey(const fpnt::KeyGenContext& ctx) override {
    const auto& pkt = ctx.pkt;
    [[maybe_unused]] auto& granularity = ctx.granularity;
    [[maybe_unused]] auto file_idx = ctx.file_idx;

    std::string cur_key;
    nlohmann::json key_data;

    std::string cur_src = safe_get_string(pkt, "_ws.col.def_src");
    std::string cur_dst = safe_get_string(pkt, "_ws.col.def_dst");

    // fix a bug in tshark
    // sometimes, ip.src or ip.dst can have unexpected comma due to a bug in tshark. we will use the
    // first part of the address

    size_t l;
    if ((l = cur_src.find(',')) != std::string::npos) {
      cur_src = cur_src.substr(0, l);
    }
    if ((l = cur_dst.find(',')) != std::string::npos) {
      cur_dst = cur_dst.substr(0, l);
    }

    bool src_greater_equal = false;
    if (cur_src.find(':') != std::string::npos) {  // IPv6
      struct in6_addr src_n, dst_n;
      if (inet_pton(AF_INET6, std::string(cur_src).c_str(), &src_n) != 1
          || inet_pton(AF_INET6, std::string(cur_dst).c_str(), &dst_n) != 1) {
        std::cerr << "Invalid IPv6 address" << std::endl;
        exit(EXIT_FAILURE);
      }
      if (memcmp(&src_n, &dst_n, sizeof(src_n)) >= 0) src_greater_equal = true;
    } else {  // IPv4
      struct in_addr src_n, dst_n;
      if (inet_pton(AF_INET, std::string(cur_src).c_str(), &src_n) != 1
          || inet_pton(AF_INET, std::string(cur_dst).c_str(), &dst_n) != 1) {
        std::cerr << "Invalid IPv4 address" << std::endl;
        exit(EXIT_FAILURE);
      }
      // Compare in network byte order (Big Endian)
      if (memcmp(&src_n, &dst_n, sizeof(src_n)) >= 0) src_greater_equal = true;
    }

    if (src_greater_equal)
      cur_key = fmt::format("{0},{1}", cur_dst, cur_src);
    else
      cur_key = fmt::format("{1},{0}", cur_dst, cur_src);

    key_data["__" + granularity + "_key"] = cur_key;
    return key_data;
  }
};
extern "C" fpnt::KeyGenerator* create_genKey_flowset_default() {
  return new GenKey_flowset_default();
}

/** @brief A key generator for "bidirectional" Flow records assuming only IPv4 datagrams are
 * available for efficient generation; use ip.src and ip.dst fields; suitable for encrypted traffic
 * analysis such as TLS or QUIC; note that the host with smaller IP address is appeared first;
 * non-IPv4 packets will have flow key string "{file_idx}_NonIPv4".
 */
class GenKey_flowset_ipv4 : public fpnt::KeyGenerator {
public:
  GenKey_flowset_ipv4() : fpnt::KeyGenerator({"ip.src", "ip.dst"}) {}
  nlohmann::json genKey(const fpnt::KeyGenContext& ctx) override {
    const auto& pkt = ctx.pkt;
    [[maybe_unused]] auto& granularity = ctx.granularity;
    [[maybe_unused]] auto file_idx = ctx.file_idx;

    std::string cur_key;
    nlohmann::json key_data;

    std::string cur_src = safe_get_string(pkt, "ip.src");
    std::string cur_dst = safe_get_string(pkt, "ip.dst");

    // if NonIPv4 address is given... ;<
    if (cur_src.empty() && cur_dst.empty()) {
      key_data["__" + granularity + "_key"] = std::to_string(file_idx) + "_NonIPv4";
      return key_data;  // the only location to use dispatcher's file_idx
    }

    // fix a bug in tshark
    // sometimes, ip.src or ip.dst can have unexpected comma due to a bug in tshark. we will use the
    // first part of the address

    size_t l;
    if ((l = cur_src.find(',')) != std::string::npos) {
      cur_src = cur_src.substr(0, l);
    }
    if ((l = cur_dst.find(',')) != std::string::npos) {
      cur_dst = cur_dst.substr(0, l);
    }

    struct in_addr src_n, dst_n;
    if (inet_aton(std::string(cur_src).c_str(), &src_n) == 0
        || inet_aton(std::string(cur_dst).c_str(), &dst_n) == 0) {
      std::cerr << "Invalid address" << std::endl;
      exit(EXIT_FAILURE);
    }
    if (src_n.s_addr >= dst_n.s_addr)
      cur_key = fmt::format("{0},{1}", cur_dst, cur_src);
    else
      cur_key = fmt::format("{1},{0}", cur_dst, cur_src);

    key_data["__" + granularity + "_key"] = cur_key;
    return key_data;
  }
};
extern "C" fpnt::KeyGenerator* create_genKey_flowset_ipv4() { return new GenKey_flowset_ipv4(); }

/** @brief A sample key generator for Compressed Beamforming Report; we use 'packet' to refer a IEEE
 * 802.11 frame
 *
 */
class GenKey_pkt_cbr : public fpnt::KeyGenerator {
public:
  GenKey_pkt_cbr() : fpnt::KeyGenerator({"idx", "wlan.ta", "wlan.ra"}) {}
  nlohmann::json genKey(const fpnt::KeyGenContext& ctx) override {
    const auto& pkt = ctx.pkt;
    [[maybe_unused]] auto& granularity = ctx.granularity;
    [[maybe_unused]] auto file_idx = ctx.file_idx;

    nlohmann::json key_data;
    key_data["__" + granularity + "_key"] = std::to_string(pkt["idx"].get<size_t>()) + "_"
                                            + safe_get_string(pkt, "wlan.ra") + "_"
                                            + safe_get_string(pkt, "wlan.ta");
    return key_data;
  }
};
extern "C" fpnt::KeyGenerator* create_genKey_pkt_cbr() { return new GenKey_pkt_cbr(); }

class GenKey_protocol_default : public fpnt::KeyGenerator {
public:
  GenKey_protocol_default() : fpnt::KeyGenerator({"_ws.col.protocol"}) {}
  nlohmann::json genKey(const fpnt::KeyGenContext& ctx) override {
    const auto& pkt = ctx.pkt;
    [[maybe_unused]] auto& granularity = ctx.granularity;
    [[maybe_unused]] auto file_idx = ctx.file_idx;

    nlohmann::json key_data;
    key_data["__" + granularity + "_key"] = safe_get_string(pkt, "_ws.col.protocol");
    return key_data;
  }
};
extern "C" fpnt::KeyGenerator* create_genKey_protocol_default() {
  return new GenKey_protocol_default();
}
