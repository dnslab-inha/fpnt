#include "default_keygen.h"
#include "dispatcher_ptr.h"
#include <arpa/inet.h>
#include <fmt/core.h>


/** @brief Default key generator for Packet records; just use its record creation order starting from 0
 * 
 */
const std::string genKey_pkt_default(const nlohmann::json& pkt, std::string& granularity, std::string& key) {
    return std::to_string(pkt["idx"].get<size_t>());
}

/** @brief Default key generator for "bidirectional" Flow records assuming only TCP/IPv4, UDP/IPv4 datagrams are available for efficient generation; use 4 tuple fields (tcp.srcport, tcp.dstport, udp.srcport, udp.dstport, ip.src, ip.dst); suitable for encrypted traffic analysis such as TLS or QUIC; note that the host with smaller port number is appeared first (to identify well-known service port quickly) and if the port numbers are the same, the host with smaller IP address is appeared first.
 * 
 */
const std::string genKey_flow_default(const nlohmann::json& pkt, std::string& granularity, std::string& key) {
    std::string cur_key;
    //std::string cur_srcport = std::to_string(pkt["tcp.srcport"].get<std::size_t>());
    //std::string cur_dstport = std::to_string(pkt["tcp.dstport"].get<std::size_t>());
    std::string cur_srcport = pkt["tcp.srcport"].get<std::string>();
    std::string cur_dstport = pkt["tcp.dstport"].get<std::string>();

    // Support for Protocol Name
    std::string protocol_name = "TCP";

    if (cur_srcport.compare("") == 0 || cur_dstport.compare("") == 0)
    {
        protocol_name = "UDP";

        if (pkt["udp.srcport"].is_null() || pkt["udp.dstport"].is_null())
        {
            std::cerr << "getPktKey: the corresponding input json does not collect udp.srcport and/or udp.dstport." << std::endl;
            std::cerr << "getPktKey: When tshark is used and UDP flows are needless, tshark must filter off UDP packets." << std::endl;
            exit(EXIT_FAILURE);
        }

        //cur_srcport = std::to_string(pkt["udp.srcport"].get<std::size_t>());
        //cur_dstport = std::to_string(pkt["udp.dstport"].get<std::size_t>());
        cur_srcport = pkt["udp.srcport"].get<std::string>();
        cur_dstport = pkt["udp.dstport"].get<std::string>();

        if (cur_srcport.compare("") == 0 || cur_dstport.compare("") == 0)
        {
            protocol_name = "etc";

            cur_srcport = "0";
            cur_dstport = "0";
        }
    }

    // end of Support for Protocol Name

    std::string cur_src = pkt["ip.src"].get<std::string>();
    std::string cur_dst = pkt["ip.dst"].get<std::string>();

    // if IPv6 address is given... ;<
    if (cur_src + cur_dst == "")
    {
        std::cerr << "genKey_flow_default: A non IPv4 packet (maybe IPv6?) will have flow key string ``IPv6''" << std::endl;
        return std::to_string(fpnt::d->file_idx) + "_IPv6"; // the only location to use dispatcher's file_idx
    }

    // fix a bug in tshark
    // sometimes, ip.src or ip.dst can have unexpected comma due to a bug in tshark. we will use the first part of the address

    size_t l;
    //	string cur_src_backup = "", cur_dst_backup = "";
    if ((l = cur_src.find(',')) != std::string::npos)
    {
        // cout << "uuu...." << cur_src << endl;
        //		cur_src_backup = cur_src;
        cur_src = cur_src.substr(0, l);
    }
    if ((l = cur_dst.find(',')) != std::string::npos)
    {
        // cout << "uuu....dst..." << cur_dst << endl;
        //		cur_dst_backup = cur_dst;
        cur_dst = cur_dst.substr(0, l);
    }

    int keycomp = atoi(cur_srcport.c_str()) - atoi(cur_dstport.c_str());
    if (keycomp == 0)
    {
        // In case of UDP, there are many cases that src port and dst port are the same
        // in this case, we choose the decreasing order; that is a kind of lexicographical order is used.
        // printf("implusible situation!\n");
        // exit(1);

        struct in_addr src_n, dst_n;
        if (inet_aton(cur_src.c_str(), &src_n) == 0 || inet_aton(cur_dst.c_str(), &dst_n) == 0)
        {
            std::cerr << "Invalid address" << std::endl;
            exit(EXIT_FAILURE);
        }
        if (src_n.s_addr >= dst_n.s_addr)
            cur_key = fmt::format("{0}:{1},{2}:{3}", cur_dst, cur_dstport, cur_src, cur_srcport);
        else
            cur_key = fmt::format("{2}:{3},{0}:{1}", cur_dst, cur_dstport, cur_src, cur_srcport);
    }
    else if (keycomp > 0)
    { // srcport > dstport
        cur_key = fmt::format("{0}:{1},{2}:{3}", cur_dst, cur_dstport, cur_src, cur_srcport);
    }
    else
    { // srcport < dstport
        cur_key = fmt::format("{2}:{3},{0}:{1}", cur_dst, cur_dstport, cur_src, cur_srcport);
    }
    return cur_key;
}

/** @brief A key generator for "directional" Flow records assuming only TCP/IPv4, UDP/IPv4 datagrams are available for efficient generation; use 4 tuple fields (tcp.srcport, tcp.dstport, udp.srcport, udp.dstport, ip.src, ip.dst); suitable for encrypted traffic analysis such as TLS or QUIC; key string is "srcIP:srcPort,dstIP,dstPort".
 * 
 */
const std::string genKey_flow_directional(const nlohmann::json& pkt, std::string& granularity, std::string& key) {
    std::string cur_key;
    //std::string cur_srcport = std::to_string(pkt["tcp.srcport"].get<std::size_t>());
    //std::string cur_dstport = std::to_string(pkt["tcp.dstport"].get<std::size_t>());
    std::string cur_srcport = pkt["tcp.srcport"].get<std::string>();
    std::string cur_dstport = pkt["tcp.dstport"].get<std::string>();

    // Support for Protocol Name
    std::string protocol_name = "TCP";

    if (cur_srcport.compare("") == 0 || cur_dstport.compare("") == 0)
    {
        protocol_name = "UDP";

        if (pkt["udp.srcport"].is_null() || pkt["udp.dstport"].is_null())
        {
            std::cerr << "getPktKey: the corresponding input json does not collect udp.srcport and/or udp.dstport." << std::endl;
            std::cerr << "getPktKey: When tshark is used and UDP flows are needless, tshark must filter off UDP packets." << std::endl;
            exit(EXIT_FAILURE);
        }

        //cur_srcport = std::to_string(pkt["udp.srcport"].get<std::size_t>());
        //cur_dstport = std::to_string(pkt["udp.dstport"].get<std::size_t>());
        cur_srcport = pkt["udp.srcport"].get<std::string>();
        cur_dstport = pkt["udp.dstport"].get<std::string>();

        if (cur_srcport.compare("") == 0 || cur_dstport.compare("") == 0)
        {
            protocol_name = "etc";

            cur_srcport = "0";
            cur_dstport = "0";
        }
    }

    // end of Support for Protocol Name

    std::string cur_src = pkt["ip.src"].get<std::string>();
    std::string cur_dst = pkt["ip.dst"].get<std::string>();

    // if IPv6 address is given... ;<
    if (cur_src + cur_dst == "")
    {
        std::cerr << "genKey_flow_default: A non IPv4 packet (maybe IPv6?) will have flow key string ``IPv6''" << std::endl;
        return std::to_string(fpnt::d->file_idx) + "_IPv6"; // the only location to use dispatcher's file_idx
    }

    // fix a bug in tshark
    // sometimes, ip.src or ip.dst can have unexpected comma due to a bug in tshark. we will use the first part of the address

    size_t l;
    //	string cur_src_backup = "", cur_dst_backup = "";
    if ((l = cur_src.find(',')) != std::string::npos)
    {
        // cout << "uuu...." << cur_src << endl;
        //		cur_src_backup = cur_src;
        cur_src = cur_src.substr(0, l);
    }
    if ((l = cur_dst.find(',')) != std::string::npos)
    {
        // cout << "uuu....dst..." << cur_dst << endl;
        //		cur_dst_backup = cur_dst;
        cur_dst = cur_dst.substr(0, l);
    }

    cur_key = fmt::format("{0}:{1},{2}:{3}", cur_src, cur_srcport, cur_dst, cur_dstport);

    return cur_key;
}

/** @brief Default key generator for "bidirectional" Flow records assuming only IPv4 datagrams are available for efficient generation; use ip.src and ip.dst fields; suitable for encrypted traffic analysis such as TLS or QUIC; note that the host with smaller IP address is appeared first
 * 
 */
const std::string genKey_flowset_default(const nlohmann::json& pkt, std::string& granularity, std::string& key) {
    std::string cur_key;

    std::string cur_src = pkt["ip.src"].get<std::string>();
    std::string cur_dst = pkt["ip.dst"].get<std::string>();

    // if IPv6 address is given... ;<
    if (cur_src + cur_dst == "")
    {
        std::cerr << "genKey_flowset_default: A non IPv4 packet (maybe IPv6?) will have flow key string ``IPv6''" << std::endl;
        return std::to_string(fpnt::d->file_idx) + "_IPv6"; // the only location to use dispatcher's file_idx
    }

    // fix a bug in tshark
    // sometimes, ip.src or ip.dst can have unexpected comma due to a bug in tshark. we will use the first part of the address

    size_t l;
    //	string cur_src_backup = "", cur_dst_backup = "";
    if ((l = cur_src.find(',')) != std::string::npos)
    {
        // cout << "uuu...." << cur_src << endl;
        //		cur_src_backup = cur_src;
        cur_src = cur_src.substr(0, l);
    }
    if ((l = cur_dst.find(',')) != std::string::npos)
    {
        // cout << "uuu....dst..." << cur_dst << endl;
        //		cur_dst_backup = cur_dst;
        cur_dst = cur_dst.substr(0, l);
    }

    struct in_addr src_n, dst_n;
    if (inet_aton(cur_src.c_str(), &src_n) == 0 || inet_aton(cur_dst.c_str(), &dst_n) == 0)
    {
        std::cerr << "Invalid address" << std::endl;
        exit(EXIT_FAILURE);
    }
    if (src_n.s_addr >= dst_n.s_addr)
        cur_key = fmt::format("{0},{1}", cur_dst, cur_src);
    else
        cur_key = fmt::format("{1},{0}", cur_dst, cur_src);

    return cur_key;
}

/** @brief A sample key generator for Compressed Beamforming Report; we use 'packet' to refer a IEEE 802.11 frame
 * 
 */
const std::string genKey_pkt_cbr(const nlohmann::json& pkt, std::string& granularity, std::string& key) {
    return std::to_string(pkt["idx"].get<size_t>()) + "_" + pkt["wlan.ra"].get<std::string>() + "_" + pkt["wlan.ta"].get<std::string>();
}

const std::string genKey_protocol_default(const nlohmann::json& pkt, std::string& granularity, std::string& key) {
    return pkt["_ws.col.protocol"].get<std::string>();
}