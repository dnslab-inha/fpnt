#include "default_keygen.h"

#include <arpa/inet.h>
#include <fmt/core.h>

#include <cstring>

#include "dispatcher_ptr.h"

/** @brief Default key generator for Packet records;
 * just use its record creation order starting from 0
 *
 */
const std::string genKey_pkt_default(const nlohmann::json& pkt, std::string& granularity,
                                     std::string& key) {
  return std::to_string(pkt["idx"].get<size_t>());
}

/** @brief Default key generator for "bidirectional" Flow records assuming only TCP/IP, UDP/IP
 * datagrams are available for efficient generation; use "4 tuple" fields (_ws.col.def_src,
 * _ws.col.def_dst, tcp.srcport or udp.srcport, tcp.dstport or udp.dstport); suitable for
 * encrypted traffic analysis such as TLS or QUIC; note that the host with smaller port number
 * is appeared first (to identify well-known service port quickly) and if the port numbers are
 * the same, the host with smaller IP address is appeared first.
 */
const std::string genKey_flow_default(const nlohmann::json& pkt, std::string& granularity,
                                      std::string& key) {
  std::string cur_key;

  std::string cur_srcport = pkt["tcp.srcport"].get<std::string>();
  std::string cur_dstport = pkt["tcp.dstport"].get<std::string>();

  // Support for Protocol Name
  std::string protocol_name = "TCP";

  if (cur_srcport.compare("") == 0 || cur_dstport.compare("") == 0) {
    protocol_name = "UDP";

    // Previously, when udp.srcport or udp.dstport is null, it was treated as an error to indicate
    // user to check fpnt is correctly configured. However, in some cases, UDP port information
    // might be missing, especially when analyzing certain types of traffic. To this end, we will
    // set both ports to "0" when they are missing.
    if (pkt["udp.srcport"].is_null() || pkt["udp.dstport"].is_null()) {
      cur_srcport = "0";
      cur_dstport = "0";
    }

    cur_srcport = pkt["udp.srcport"].get<std::string>();
    cur_dstport = pkt["udp.dstport"].get<std::string>();

    if (cur_srcport.compare("") == 0 || cur_dstport.compare("") == 0) {
      protocol_name = "etc";

      cur_srcport = "0";
      cur_dstport = "0";
    }
  }

  // end of Support for Protocol Name

  std::string cur_src = pkt["_ws.col.def_src"].get<std::string>();
  std::string cur_dst = pkt["_ws.col.def_dst"].get<std::string>();

  // std::cout << cur_src << "," << cur_dst << std::endl;

  // fix a bug in tshark
  // sometimes, ip.src or ip.dst can have unexpected comma due to a bug in tshark. we will use the
  // first part of the address

  size_t l;
  //	string cur_src_backup = "", cur_dst_backup = "";
  if ((l = cur_src.find(',')) != std::string::npos) {
    // cout << "uuu...." << cur_src << endl;
    //		cur_src_backup = cur_src;
    cur_src = cur_src.substr(0, l);
  }
  if ((l = cur_dst.find(',')) != std::string::npos) {
    // cout << "uuu....dst..." << cur_dst << endl;
    //		cur_dst_backup = cur_dst;
    cur_dst = cur_dst.substr(0, l);
  }

  // flow key generation policy:
  // We assume that smaller port number address is the server;
  // if the port number address is the same (found in many UDP cases),
  //    we assume that the smaller IP address is the server
  // We use the client-first, server-second pair

  int keycomp = atoi(cur_srcport.c_str()) - atoi(cur_dstport.c_str());
  if (keycomp == 0)  // the port number same case
  {
    bool src_greater_equal = false;
    if (cur_src.find(':') != std::string::npos) {  // IPv6
      struct in6_addr src_n, dst_n;
      if (inet_pton(AF_INET6, cur_src.c_str(), &src_n) != 1
          || inet_pton(AF_INET6, cur_dst.c_str(), &dst_n) != 1) {
        std::cerr << "Invalid IPv6 address" << std::endl;
        std::cerr << pkt["idx"].get<std::string>() << ","
                  << pkt["_ws.col.def_src"].get<std::string>() << ","
                  << pkt["_ws.col.def_dst"].get<std::string>() << std::endl;
        exit(EXIT_FAILURE);
      }
      if (memcmp(&src_n, &dst_n, sizeof(src_n)) >= 0) src_greater_equal = true;
    } else {  // IPv4
      struct in_addr src_n, dst_n;
      if (inet_pton(AF_INET, cur_src.c_str(), &src_n) != 1
          || inet_pton(AF_INET, cur_dst.c_str(), &dst_n) != 1) {
        std::cerr << "Invalid IPv4 address" << std::endl;
        std::cerr << pkt["idx"].get<std::string>() << ","
                  << pkt["_ws.col.def_src"].get<std::string>() << ","
                  << pkt["_ws.col.def_dst"].get<std::string>() << std::endl;
        exit(EXIT_FAILURE);
      }
      // Compare in network byte order (Big Endian)
      if (memcmp(&src_n, &dst_n, sizeof(src_n)) >= 0) src_greater_equal = true;
    }

    if (src_greater_equal)  // dst_n is the server
      cur_key = fmt::format("{0}:{1},{2}:{3}", cur_src, cur_srcport, cur_dst, cur_dstport);
    else  // dst_n is the client
      cur_key = fmt::format("{2}:{3},{0}:{1}", cur_src, cur_srcport, cur_dst, cur_dstport);
  } else if (keycomp > 0) {  // srcport > dstport                   dstport is the server
    cur_key = fmt::format("{0}:{1},{2}:{3}", cur_src, cur_srcport, cur_dst, cur_dstport);
  } else {  // srcport < dstport                   dstport is the client
    cur_key = fmt::format("{2}:{3},{0}:{1}", cur_src, cur_srcport, cur_dst, cur_dstport);
  }

  return cur_key;
}

/** @brief Default key generator for "bidirectional" Flow records assuming only TCP/IP, UDP/IP
 * datagrams are available for efficient generation; use the standard "5 tuple" fields
 * (_ws.col.def_src, _ws.col.def_dst, tcp.srcport or udp.srcport, tcp.dstport or udp.dstport,
 * protocol); suitable for encrypted traffic analysis for conventional TCP/IP protocol; note that
 * the host with smaller port number is appeared first (to identify well-known service port quickly)
 * and if the port numbers are the same, the host with smaller IP address is appeared first. key
 * string is "srcIP:srcPort,dstIP:dstPort/protocol".
 *
 */
const std::string genKey_flow_default_5tuple(const nlohmann::json& pkt, std::string& granularity,
                                             std::string& key) {
  std::string cur_key;

  std::string cur_srcport = pkt["tcp.srcport"].get<std::string>();
  std::string cur_dstport = pkt["tcp.dstport"].get<std::string>();

  // Support for Protocol Name; however, currently this variable is not used.
  std::string protocol_name = "TCP";

  // When TCP ports are missing, check UDP ports
  if (cur_srcport.compare("") == 0 || cur_dstport.compare("") == 0) {
    protocol_name = "UDP";  // We assume UDP protocol

    // Previously, when udp.srcport or udp.dstport is null, it was treated as an error to indicate
    // user to check fpnt is correctly configured. However, in some cases, UDP port information
    // might be missing, especially when analyzing certain types of traffic. To this end, we will
    // set both ports to "0" when they are missing.
    if (pkt["udp.srcport"].is_null() || pkt["udp.dstport"].is_null()) {
      cur_srcport = "0";
      cur_dstport = "0";
    }

    cur_srcport = pkt["udp.srcport"].get<std::string>();
    cur_dstport = pkt["udp.dstport"].get<std::string>();

    if (cur_srcport.compare("") == 0 || cur_dstport.compare("") == 0) {
      protocol_name = "etc";  // e.g., ICMP, ...

      cur_srcport = "0";
      cur_dstport = "0";
    }
  }

  // end of Support for Protocol Name

  std::string cur_src = pkt["_ws.col.def_src"].get<std::string>();
  std::string cur_dst = pkt["_ws.col.def_dst"].get<std::string>();

  // std::cout << cur_src << "," << cur_dst << std::endl;

  // fix a bug in tshark
  // sometimes, ip.src or ip.dst can have unexpected comma due to a bug in tshark. we will use the
  // first part of the address

  size_t l;
  //	string cur_src_backup = "", cur_dst_backup = "";
  if ((l = cur_src.find(',')) != std::string::npos) {
    // cout << "uuu...." << cur_src << endl;
    //		cur_src_backup = cur_src;
    cur_src = cur_src.substr(0, l);
  }
  if ((l = cur_dst.find(',')) != std::string::npos) {
    // cout << "uuu....dst..." << cur_dst << endl;
    //		cur_dst_backup = cur_dst;
    cur_dst = cur_dst.substr(0, l);
  }

  // flow key generation policy:
  // We assume that smaller port number address is the server;
  // if the port number address is the same (found in many UDP cases),
  //    we assume that the smaller IP address is the server
  // We use the client-first, server-second pair

  std::string ip_proto = pkt["ip.proto"].get<std::string>();

  if (ip_proto.compare("") == 0) {
    std::string ipv6_nxt = pkt["ipv6.nxt"].get<std::string>();
    ip_proto = ipv6_nxt;
  }

  int keycomp = atoi(cur_srcport.c_str()) - atoi(cur_dstport.c_str());
  if (keycomp == 0)  // the port number same case
  {
    bool src_greater_equal = false;
    if (cur_src.find(':') != std::string::npos) {  // IPv6
      struct in6_addr src_n, dst_n;
      if (inet_pton(AF_INET6, cur_src.c_str(), &src_n) != 1
          || inet_pton(AF_INET6, cur_dst.c_str(), &dst_n) != 1) {
        std::cerr << "Invalid IPv6 address" << std::endl;
        std::cerr << pkt["idx"].get<std::string>() << ","
                  << pkt["_ws.col.def_src"].get<std::string>() << ","
                  << pkt["_ws.col.def_dst"].get<std::string>() << std::endl;
        exit(EXIT_FAILURE);
      }
      if (memcmp(&src_n, &dst_n, sizeof(src_n)) >= 0) src_greater_equal = true;
    } else {  // IPv4
      struct in_addr src_n, dst_n;
      if (inet_pton(AF_INET, cur_src.c_str(), &src_n) != 1
          || inet_pton(AF_INET, cur_dst.c_str(), &dst_n) != 1) {
        std::cerr << "Invalid IPv4 address" << std::endl;
        std::cerr << pkt["idx"].get<std::string>() << ","
                  << pkt["_ws.col.def_src"].get<std::string>() << ","
                  << pkt["_ws.col.def_dst"].get<std::string>() << std::endl;
        exit(EXIT_FAILURE);
      }
      // Compare in network byte order (Big Endian)
      if (memcmp(&src_n, &dst_n, sizeof(src_n)) >= 0) src_greater_equal = true;
    }

    if (src_greater_equal)  // dst_n is the server
      cur_key = fmt::format("{0}:{1},{2}:{3}/{4}", cur_src, cur_srcport, cur_dst, cur_dstport,
                            ip_proto);
    else  // dst_n is the client
      cur_key = fmt::format("{2}:{3},{0}:{1}/{4}", cur_src, cur_srcport, cur_dst, cur_dstport,
                            ip_proto);
  } else if (keycomp > 0) {  // srcport > dstport                   dstport is the server
    cur_key
        = fmt::format("{0}:{1},{2}:{3}/{4}", cur_src, cur_srcport, cur_dst, cur_dstport, ip_proto);
  } else {  // srcport < dstport                   dstport is the client
    cur_key
        = fmt::format("{2}:{3},{0}:{1}/{4}", cur_src, cur_srcport, cur_dst, cur_dstport, ip_proto);
  }

  return cur_key;
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
const std::string genKey_flow_ipv4(const nlohmann::json& pkt, std::string& granularity,
                                   std::string& key) {
  std::string cur_key;

  std::string cur_srcport = pkt["tcp.srcport"].get<std::string>();
  std::string cur_dstport = pkt["tcp.dstport"].get<std::string>();

  // Support for Protocol Name
  std::string protocol_name = "TCP";

  if (cur_srcport.compare("") == 0 || cur_dstport.compare("") == 0) {
    protocol_name = "UDP";

    // When udp.srcport or udp.dstport is null, it was treated as an error to indicate user to check
    // fpnt is correctly configured.
    if (pkt["udp.srcport"].is_null() || pkt["udp.dstport"].is_null()) {
      std::cerr << "getPktKey: the corresponding input json does not collect udp.srcport and/or "
                   "udp.dstport."
                << std::endl;
      std::cerr << "getPktKey: When tshark is used and UDP flows are needless, tshark must filter "
                   "off UDP packets."
                << std::endl;
      exit(EXIT_FAILURE);
    }

    cur_srcport = pkt["udp.srcport"].get<std::string>();
    cur_dstport = pkt["udp.dstport"].get<std::string>();

    if (cur_srcport.compare("") == 0 || cur_dstport.compare("") == 0) {
      protocol_name = "etc";

      cur_srcport = "0";
      cur_dstport = "0";
    }
  }

  // end of Support for Protocol Name

  std::string cur_src = pkt["ip.src"].get<std::string>();
  std::string cur_dst = pkt["ip.dst"].get<std::string>();

  // if IPv6 address is given... ;<
  if (cur_src + cur_dst == "") {
    return std::to_string(fpnt::d->file_idx)
           + "_NonIPv4";  // the only location to use dispatcher's file_idx
  }

  // fix a bug in tshark
  // sometimes, ip.src or ip.dst can have unexpected comma due to a bug in tshark. we will use the
  // first part of the address

  size_t l;
  //	string cur_src_backup = "", cur_dst_backup = "";
  if ((l = cur_src.find(',')) != std::string::npos) {
    // cout << "uuu...." << cur_src << endl;
    //		cur_src_backup = cur_src;
    cur_src = cur_src.substr(0, l);
  }
  if ((l = cur_dst.find(',')) != std::string::npos) {
    // cout << "uuu....dst..." << cur_dst << endl;
    //		cur_dst_backup = cur_dst;
    cur_dst = cur_dst.substr(0, l);
  }

  // flow key generation policy:
  // We assume that smaller port number address is the server;
  // if the port number address is the same (found in many UDP cases),
  //    we assume that the smaller IP address is the server
  // We use the client-first, server-second pair

  int keycomp = atoi(cur_srcport.c_str()) - atoi(cur_dstport.c_str());
  if (keycomp == 0)  // the port number same case
  {
    struct in_addr src_n, dst_n;
    if (inet_aton(cur_src.c_str(), &src_n) == 0 || inet_aton(cur_dst.c_str(), &dst_n) == 0) {
      std::cerr << "Invalid address" << std::endl;
      exit(EXIT_FAILURE);
    }
    if (src_n.s_addr >= dst_n.s_addr)  // dst_n is the server
      cur_key = fmt::format("{0}:{1},{2}:{3}", cur_src, cur_srcport, cur_dst, cur_dstport);
    else  // dst_n is the client
      cur_key = fmt::format("{2}:{3},{0}:{1}", cur_src, cur_srcport, cur_dst, cur_dstport);
  } else if (keycomp > 0) {  // srcport > dstport                   dstport is the server
    cur_key = fmt::format("{0}:{1},{2}:{3}", cur_src, cur_srcport, cur_dst, cur_dstport);
  } else {  // srcport < dstport                   dstport is the client
    cur_key = fmt::format("{2}:{3},{0}:{1}", cur_src, cur_srcport, cur_dst, cur_dstport);
  }
  return cur_key;
}

/** @brief Default key generator for "directional" Flow records assuming only TCP/IP, UDP/IP
 * datagrams are available for efficient generation; use "4 tuple" fields (_ws.col.def_src,
 * _ws.col.def_dst, tcp.srcport or udp.srcport, tcp.dstport or udp.dstport); suitable for
 * encrypted traffic analysis such as TLS or QUIC; key string is "srcIP:srcPort,dstIP:dstPort".
 */
const std::string genKey_flow_directional_default(const nlohmann::json& pkt,
                                                  std::string& granularity, std::string& key) {
  std::string cur_key;

  std::string cur_srcport = pkt["tcp.srcport"].get<std::string>();
  std::string cur_dstport = pkt["tcp.dstport"].get<std::string>();

  // Support for Protocol Name
  std::string protocol_name = "TCP";

  if (cur_srcport.compare("") == 0 || cur_dstport.compare("") == 0) {
    protocol_name = "UDP";

    // Previously, when udp.srcport or udp.dstport is null, it was treated as an error to indicate
    // user to check fpnt is correctly configured. However, in some cases, UDP port information
    // might be missing, especially when analyzing certain types of traffic. To this end, we will
    // set both ports to "0" when they are missing.
    if (pkt["udp.srcport"].is_null() || pkt["udp.dstport"].is_null()) {
      cur_srcport = "0";
      cur_dstport = "0";
    }

    cur_srcport = pkt["udp.srcport"].get<std::string>();
    cur_dstport = pkt["udp.dstport"].get<std::string>();

    if (cur_srcport.compare("") == 0 || cur_dstport.compare("") == 0) {
      protocol_name = "etc";

      cur_srcport = "0";
      cur_dstport = "0";
    }
  }

  // end of Support for Protocol Name

  std::string cur_src = pkt["_ws.col.def_src"].get<std::string>();
  std::string cur_dst = pkt["_ws.col.def_dst"].get<std::string>();

  // fix a bug in tshark
  // sometimes, ip.src or ip.dst can have unexpected comma due to a bug in tshark. we will use the
  // first part of the address

  size_t l;
  //	string cur_src_backup = "", cur_dst_backup = "";
  if ((l = cur_src.find(',')) != std::string::npos) {
    // cout << "uuu...." << cur_src << endl;
    //		cur_src_backup = cur_src;
    cur_src = cur_src.substr(0, l);
  }
  if ((l = cur_dst.find(',')) != std::string::npos) {
    // cout << "uuu....dst..." << cur_dst << endl;
    //		cur_dst_backup = cur_dst;
    cur_dst = cur_dst.substr(0, l);
  }

  cur_key = fmt::format("{0}:{1},{2}:{3}", cur_src, cur_srcport, cur_dst, cur_dstport);

  return cur_key;
}

/** @brief A key generator for "directional" Flow records assuming only TCP/IPv4, UDP/IPv4 datagrams
 * are available for efficient generation; use 4 tuple fields (ip.src,
 * ip.dst, tcp.srcport or udp.srcport, tcp.dstport or udp.dstport); suitable for
 * IPv4 traffic analysis only; key string is "srcIP:srcPort,dstIP:dstPort".
 * non-IPv4 packets will have flow key string "{file_idx}_NonIPv4".
 */
const std::string genKey_flow_directional_ipv4(const nlohmann::json& pkt, std::string& granularity,
                                               std::string& key) {
  std::string cur_key;

  std::string cur_srcport = pkt["tcp.srcport"].get<std::string>();
  std::string cur_dstport = pkt["tcp.dstport"].get<std::string>();

  // Support for Protocol Name
  std::string protocol_name = "TCP";

  if (cur_srcport.compare("") == 0 || cur_dstport.compare("") == 0) {
    protocol_name = "UDP";

    // When udp.srcport or udp.dstport is null, it was treated as an error to indicate user to check
    // fpnt is correctly configured.
    if (pkt["udp.srcport"].is_null() || pkt["udp.dstport"].is_null()) {
      std::cerr << "getPktKey: the corresponding input json does not collect udp.srcport and/or "
                   "udp.dstport."
                << std::endl;
      std::cerr << "getPktKey: When tshark is used and UDP flows are needless, tshark must filter "
                   "off UDP packets."
                << std::endl;
      exit(EXIT_FAILURE);
    }

    cur_srcport = pkt["udp.srcport"].get<std::string>();
    cur_dstport = pkt["udp.dstport"].get<std::string>();

    if (cur_srcport.compare("") == 0 || cur_dstport.compare("") == 0) {
      protocol_name = "etc";

      cur_srcport = "0";
      cur_dstport = "0";
    }
  }

  // end of Support for Protocol Name

  std::string cur_src = pkt["ip.src"].get<std::string>();
  std::string cur_dst = pkt["ip.dst"].get<std::string>();

  // if IPv6 address is given... ;<
  if (cur_src + cur_dst == "") {
    return std::to_string(fpnt::d->file_idx)
           + "_NonIPv4";  // the only location to use dispatcher's file_idx
  }

  // fix a bug in tshark
  // sometimes, ip.src or ip.dst can have unexpected comma due to a bug in tshark. we will use the
  // first part of the address

  size_t l;
  //	string cur_src_backup = "", cur_dst_backup = "";
  if ((l = cur_src.find(',')) != std::string::npos) {
    // cout << "uuu...." << cur_src << endl;
    //		cur_src_backup = cur_src;
    cur_src = cur_src.substr(0, l);
  }
  if ((l = cur_dst.find(',')) != std::string::npos) {
    // cout << "uuu....dst..." << cur_dst << endl;
    //		cur_dst_backup = cur_dst;
    cur_dst = cur_dst.substr(0, l);
  }

  cur_key = fmt::format("{0}:{1},{2}:{3}", cur_src, cur_srcport, cur_dst, cur_dstport);

  return cur_key;
}

/** @brief Default key generator for "directional" Flow records assuming only TCP/IP, UDP/IP
 * datagrams are available for efficient generation; the standard "5 tuple" fields
 * (_ws.col.def_src, _ws.col.def_dst, tcp.srcport or udp.srcport, tcp.dstport or udp.dstport,
 * protocol); suitable for encrypted traffic analysis for conventional TCP/IP protocol; key string
 * is "srcIP:srcPort,dstIP:dstPort/protocol".
 */
const std::string genKey_flow_directional_default_5tuple(const nlohmann::json& pkt,
                                                         std::string& granularity,
                                                         std::string& key) {
  std::string cur_key;

  std::string cur_srcport = pkt["tcp.srcport"].get<std::string>();
  std::string cur_dstport = pkt["tcp.dstport"].get<std::string>();

  // Support for Protocol Name
  std::string protocol_name = "TCP";

  if (cur_srcport.compare("") == 0 || cur_dstport.compare("") == 0) {
    protocol_name = "UDP";

    // Previously, when udp.srcport or udp.dstport is null, it was treated as an error to indicate
    // user to check fpnt is correctly configured. However, in some cases, UDP port information
    // might be missing, especially when analyzing certain types of traffic. To this end, we will
    // set both ports to "0" when they are missing.
    if (pkt["udp.srcport"].is_null() || pkt["udp.dstport"].is_null()) {
      cur_srcport = "0";
      cur_dstport = "0";
    }

    cur_srcport = pkt["udp.srcport"].get<std::string>();
    cur_dstport = pkt["udp.dstport"].get<std::string>();

    if (cur_srcport.compare("") == 0 || cur_dstport.compare("") == 0) {
      protocol_name = "etc";

      cur_srcport = "0";
      cur_dstport = "0";
    }
  }

  // end of Support for Protocol Name

  std::string cur_src = pkt["_ws.col.def_src"].get<std::string>();
  std::string cur_dst = pkt["_ws.col.def_dst"].get<std::string>();

  // fix a bug in tshark
  // sometimes, ip.src or ip.dst can have unexpected comma due to a bug in tshark. we will use the
  // first part of the address

  size_t l;
  //	string cur_src_backup = "", cur_dst_backup = "";
  if ((l = cur_src.find(',')) != std::string::npos) {
    // cout << "uuu...." << cur_src << endl;
    //		cur_src_backup = cur_src;
    cur_src = cur_src.substr(0, l);
  }
  if ((l = cur_dst.find(',')) != std::string::npos) {
    // cout << "uuu....dst..." << cur_dst << endl;
    //		cur_dst_backup = cur_dst;
    cur_dst = cur_dst.substr(0, l);
  }

  std::string ip_proto = pkt["ip.proto"].get<std::string>();

  if (ip_proto.compare("") == 0) {
    std::string ipv6_nxt = pkt["ipv6.nxt"].get<std::string>();
    ip_proto = ipv6_nxt;
  }

  cur_key
      = fmt::format("{0}:{1},{2}:{3}/{4}", cur_src, cur_srcport, cur_dst, cur_dstport, ip_proto);

  return cur_key;
}

/** @brief A key generator for "directional" Flow records assuming only TCP/IPv4, UDP/IPv4 datagrams
 * are available for efficient generation; use 4 tuple fields (ip.src,
 * ip.dst, tcp.srcport or udp.srcport, tcp.dstport or udp.dstport); suitable for
 * IPv4 traffic analysis only; key string is "srcIP:srcPort,dstIP:dstPort".
 * non-IPv4 packets will have flow key string "{file_idx}_NonIPv4".
 */
const std::string genKey_flow_directional_ipv4_5tuple(const nlohmann::json& pkt,
                                                      std::string& granularity, std::string& key) {
  std::string cur_key;

  std::string cur_srcport = pkt["tcp.srcport"].get<std::string>();
  std::string cur_dstport = pkt["tcp.dstport"].get<std::string>();

  // Support for Protocol Name
  std::string protocol_name = "TCP";

  if (cur_srcport.compare("") == 0 || cur_dstport.compare("") == 0) {
    protocol_name = "UDP";

    // When udp.srcport or udp.dstport is null, it was treated as an error to indicate user to check
    // fpnt is correctly configured.
    if (pkt["udp.srcport"].is_null() || pkt["udp.dstport"].is_null()) {
      std::cerr << "getPktKey: the corresponding input json does not collect udp.srcport and/or "
                   "udp.dstport."
                << std::endl;
      std::cerr << "getPktKey: When tshark is used and UDP flows are needless, tshark must filter "
                   "off UDP packets."
                << std::endl;
      exit(EXIT_FAILURE);
    }

    cur_srcport = pkt["udp.srcport"].get<std::string>();
    cur_dstport = pkt["udp.dstport"].get<std::string>();

    if (cur_srcport.compare("") == 0 || cur_dstport.compare("") == 0) {
      protocol_name = "etc";

      cur_srcport = "0";
      cur_dstport = "0";
    }
  }

  // end of Support for Protocol Name

  std::string cur_src = pkt["ip.src"].get<std::string>();
  std::string cur_dst = pkt["ip.dst"].get<std::string>();

  // if IPv6 address is given... ;<
  if (cur_src + cur_dst == "") {
    return std::to_string(fpnt::d->file_idx)
           + "_NonIPv4";  // the only location to use dispatcher's file_idx
  }

  // fix a bug in tshark
  // sometimes, ip.src or ip.dst can have unexpected comma due to a bug in tshark. we will use the
  // first part of the address

  size_t l;
  //	string cur_src_backup = "", cur_dst_backup = "";
  if ((l = cur_src.find(',')) != std::string::npos) {
    // cout << "uuu...." << cur_src << endl;
    //		cur_src_backup = cur_src;
    cur_src = cur_src.substr(0, l);
  }
  if ((l = cur_dst.find(',')) != std::string::npos) {
    // cout << "uuu....dst..." << cur_dst << endl;
    //		cur_dst_backup = cur_dst;
    cur_dst = cur_dst.substr(0, l);
  }

  std::string ip_proto = pkt["ip.proto"].get<std::string>();

  if (ip_proto.compare("") == 0) {
    std::string ipv6_nxt = pkt["ipv6.nxt"].get<std::string>();
    ip_proto = ipv6_nxt;
  }

  cur_key
      = fmt::format("{0}:{1},{2}:{3}/{4}", cur_src, cur_srcport, cur_dst, cur_dstport, ip_proto);

  return cur_key;
}

/** @brief Default key generator for "bidirectional" Flow records assuming only IPv4 datagrams are
 * available for efficient generation; use _ws.col.def_src and _ws.col.def_dst fields; suitable for
 * encrypted traffic analysis such as TLS or QUIC; note that the host with smaller IP address is
 * appeared first
 *
 */
const std::string genKey_flowset_default(const nlohmann::json& pkt, std::string& granularity,
                                         std::string& key) {
  std::string cur_key;

  std::string cur_src = pkt["_ws.col.def_src"].get<std::string>();
  std::string cur_dst = pkt["_ws.col.def_dst"].get<std::string>();

  // fix a bug in tshark
  // sometimes, ip.src or ip.dst can have unexpected comma due to a bug in tshark. we will use the
  // first part of the address

  size_t l;
  //	string cur_src_backup = "", cur_dst_backup = "";
  if ((l = cur_src.find(',')) != std::string::npos) {
    // cout << "uuu...." << cur_src << endl;
    //		cur_src_backup = cur_src;
    cur_src = cur_src.substr(0, l);
  }
  if ((l = cur_dst.find(',')) != std::string::npos) {
    // cout << "uuu....dst..." << cur_dst << endl;
    //		cur_dst_backup = cur_dst;
    cur_dst = cur_dst.substr(0, l);
  }

  bool src_greater_equal = false;
  if (cur_src.find(':') != std::string::npos) {  // IPv6
    struct in6_addr src_n, dst_n;
    if (inet_pton(AF_INET6, cur_src.c_str(), &src_n) != 1
        || inet_pton(AF_INET6, cur_dst.c_str(), &dst_n) != 1) {
      std::cerr << "Invalid IPv6 address" << std::endl;
      exit(EXIT_FAILURE);
    }
    if (memcmp(&src_n, &dst_n, sizeof(src_n)) >= 0) src_greater_equal = true;
  } else {  // IPv4
    struct in_addr src_n, dst_n;
    if (inet_pton(AF_INET, cur_src.c_str(), &src_n) != 1
        || inet_pton(AF_INET, cur_dst.c_str(), &dst_n) != 1) {
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

  return cur_key;
}

/** @brief A key generator for "bidirectional" Flow records assuming only IPv4 datagrams are
 * available for efficient generation; use ip.src and ip.dst fields; suitable for encrypted traffic
 * analysis such as TLS or QUIC; note that the host with smaller IP address is appeared first;
 * non-IPv4 packets will have flow key string "{file_idx}_NonIPv4".
 */
const std::string genKey_flowset_ipv4(const nlohmann::json& pkt, std::string& granularity,
                                      std::string& key) {
  std::string cur_key;

  std::string cur_src = pkt["ip.src"].get<std::string>();
  std::string cur_dst = pkt["ip.dst"].get<std::string>();

  // if NonIPv4 address is given... ;<
  if (cur_src + cur_dst == "") {
    return std::to_string(fpnt::d->file_idx)
           + "_NonIPv4";  // the only location to use dispatcher's file_idx
  }

  // fix a bug in tshark
  // sometimes, ip.src or ip.dst can have unexpected comma due to a bug in tshark. we will use the
  // first part of the address

  size_t l;
  //	string cur_src_backup = "", cur_dst_backup = "";
  if ((l = cur_src.find(',')) != std::string::npos) {
    // cout << "uuu...." << cur_src << endl;
    //		cur_src_backup = cur_src;
    cur_src = cur_src.substr(0, l);
  }
  if ((l = cur_dst.find(',')) != std::string::npos) {
    // cout << "uuu....dst..." << cur_dst << endl;
    //		cur_dst_backup = cur_dst;
    cur_dst = cur_dst.substr(0, l);
  }

  struct in_addr src_n, dst_n;
  if (inet_aton(cur_src.c_str(), &src_n) == 0 || inet_aton(cur_dst.c_str(), &dst_n) == 0) {
    std::cerr << "Invalid address" << std::endl;
    exit(EXIT_FAILURE);
  }
  if (src_n.s_addr >= dst_n.s_addr)
    cur_key = fmt::format("{0},{1}", cur_dst, cur_src);
  else
    cur_key = fmt::format("{1},{0}", cur_dst, cur_src);

  return cur_key;
}

/** @brief A sample key generator for Compressed Beamforming Report; we use 'packet' to refer a IEEE
 * 802.11 frame
 *
 */
const std::string genKey_pkt_cbr(const nlohmann::json& pkt, std::string& granularity,
                                 std::string& key) {
  return std::to_string(pkt["idx"].get<size_t>()) + "_" + pkt["wlan.ra"].get<std::string>() + "_"
         + pkt["wlan.ta"].get<std::string>();
}

const std::string genKey_protocol_default(const nlohmann::json& pkt, std::string& granularity,
                                          std::string& key) {
  return pkt["_ws.col.protocol"].get<std::string>();
}