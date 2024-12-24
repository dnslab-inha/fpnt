#include <string>
#include <utility>
#include <tuple>
#include <nlohmann/json.hpp>
#include "dispatcher_ptr.h"

#include "default_keygen.h"

extern "C" void P_debug(const std::string &out_field, std::string& option, nlohmann::json& record, fpnt::Mapper& map, size_t idx) {
    std::cout << "out_field (name): " << out_field << "\t";

    if (record[out_field].is_null()) {
          std::cout << "This out_field is currently null!" << std::endl;
          return;
    }

    std::cout << "out_field (value) : " << record[out_field].get<std::string>() << "\t";
    std::cout << "out_field (value; without get) : " << record[out_field] << "\t";
    std::cout << "Option: " << option << "\t";
    std::cout << "Out Record: " << record.dump() << "\t";
    std::cout << "Mapper: ";
    auto x = fpnt::d->map_t.getFields();
    for (int i = 0; i < x.size(); i++) {
        std::cout << x[i];
        if (i == x.size() - 1)
            std::cout << "\t";
        else
            std::cout << ", ";
    }
    std::cout << "Index (idx): " << idx << std::endl;
    std::cout << "Dispatcher pointer: " << fpnt:: d << std::endl;
    std::cout << "Dispatcher in_pkts size: " << fpnt::d->in_pkts.size() << std::endl;
    std::cout << "Accessing in_pkts using idx: " << fpnt::d->in_pkts[idx].dump() << std::endl;

    if ( idx < fpnt::d->in_pkts.size())
        std::cout << "Accessing in_pkts using idx: " << fpnt::d->in_pkts[idx].dump() << std::endl;
    else
        std::cout << "Accessing in_pkts using idx seems to be invalid." << std::endl;

    if ( idx < fpnt::d->out_pkts.size())
        std::cout << "Accessing (out_)out_pkts using idx: " << fpnt::d->out_pkts[idx].dump() << std::endl;
    else
        std::cout << "Accessing (out_)out_pkts using idx seems to be invalid." << std::endl;

    if ( idx < fpnt::d->out_flows.size())
        std::cout << "Accessing (out_)flows using idx: " << fpnt::d->out_flows[idx].dump() << std::endl;
    else
        std::cout << "Accessing (out_)flows using idx seems to be invalid." << std::endl;

    if ( idx < fpnt::d->out_flowsets.size())
        std::cout << "Accessing (out_)flowsets using idx: " << fpnt::d->out_flowsets[idx].dump() << std::endl;
    else
        std::cout << "Accessing (out_)flowsets using idx seems to be invalid." << std::endl;
}

extern "C" void P_cpy(const std::string &out_field, std::string& option, nlohmann::json& record, fpnt::Mapper& map, size_t idx) {
//    auto x = fpnt::d->map_t.getFields();
    
//    if (&map == &fpnt::d->map_pkt)
//    std::cout << "Out " << out_field << " Opt " << option << " ptr " << fpnt::d << " idx " << idx << " sz " << fpnt::d->in_pkts.size() << std::endl;
//    std::cout << fpnt::d->in_pkts[idx].dump() << std::endl;
//    std::cout << fpnt::d->in_pkts[idx][option] << std::endl;
    if(fpnt::d->in_pkts[idx][option].is_null())
        record[out_field] = "";
    else
        record[out_field] = fpnt::d->in_pkts[idx][option].get<std::string>();
}

extern "C" void P_move(const std::string &out_field, std::string& option, nlohmann::json& record, fpnt::Mapper& map, size_t idx) {
    record[out_field] = std::move(fpnt::d->in_pkts[idx][option]);
}

extern "C" void P_agg4flow(const std::string &out_field, std::string& option, nlohmann::json& record, fpnt::Mapper& map, size_t idx) {
    // option contains out_pkt field name
    // idx contains flow idx
    std::string result = "";
    bool first = true;
    for(auto & pkt_idx: fpnt::d->pkt_idxs_from_flow[record["__flow_key"]]) {
        if (first) {
            first = false;
        } else {
            result += ",";
        }
        if (!fpnt::d->out_pkts[pkt_idx][option].is_null())
            result += fpnt::d->out_pkts[pkt_idx][option].get<std::string>();
    }
    record[out_field] = result;
}

extern "C" void P_skipagg4flow(const std::string &out_field, std::string& option, nlohmann::json& record, fpnt::Mapper& map, size_t idx) {
    // option contains out_pkt field name
    // idx contains flow idx
    std::string result = "";
    bool first = true;
    for(auto & pkt_idx: fpnt::d->pkt_idxs_from_flow[record["__flow_key"]]) {
        if (!fpnt::d->out_pkts[pkt_idx][option].is_null() && fpnt::d->out_pkts[pkt_idx][option] != "") {
            if (first) {
                first = false;
            } else {
                result += ",";
            }
            
                result += fpnt::d->out_pkts[pkt_idx][option].get<std::string>();
        }
    }
    record[out_field] = result;
}



extern "C" void P_agg4flowset(const std::string &out_field, std::string& option, nlohmann::json& record, fpnt::Mapper& map, size_t idx) {
    // option contains out_pkt field name
    // idx contains flow idx
    std::string result = "";
    bool first = true;
    for(auto & pkt_idx: fpnt::d->pkt_idxs_from_flowset[record["__flowset_key"]]) {
        if (first) {
            first = false;
        } else {
            result += ",";
        }
        if (!fpnt::d->out_pkts[pkt_idx][option].is_null())
            result += fpnt::d->out_pkts[pkt_idx][option].get<std::string>();
    }
    record[out_field] = result;
}

extern "C" void P_skipagg4flowset(const std::string &out_field, std::string& option, nlohmann::json& record, fpnt::Mapper& map, size_t idx) {
    // option contains out_pkt field name
    // idx contains flow idx
    std::string result = "";
    bool first = true;
    for(auto & pkt_idx: fpnt::d->pkt_idxs_from_flowset[record["__flowset_key"]]) {
        if (!fpnt::d->out_pkts[pkt_idx][option].is_null() && fpnt::d->out_pkts[pkt_idx][option] != "") {
            if (first) {
                first = false;
            } else {
                result += ",";
            }
                result += fpnt::d->out_pkts[pkt_idx][option].get<std::string>();
        }
    }
    record[out_field] = result;
}



/** P_fill1: fill if empty
 * 
 */
extern "C" void P_fill1(const std::string &out_field, std::string& option, nlohmann::json& record, fpnt::Mapper& map, size_t idx) {
    if(record[out_field] == "")
      record[out_field] = fpnt::d->in_pkts[idx][option];
}

/** P_fillOpt: fill with option value
 * 
 */
extern "C" void P_fillOpt(const std::string &out_field, std::string& option, nlohmann::json& record, fpnt::Mapper& map, size_t idx) {
    record[out_field] = option;
}

extern "C" void P_saveFlowKey(const std::string &out_field, std::string& option, nlohmann::json& record, fpnt::Mapper& map, size_t idx) {
    record[out_field] = record["__flow_key"];
}

extern "C" void P_saveFlowsetKey(const std::string &out_field, std::string& option, nlohmann::json& record, fpnt::Mapper& map, size_t idx) {
    record[out_field] = record["__flowset_key"];
}

extern "C" void P_savePktKey(const std::string &out_field, std::string& option, nlohmann::json& record, fpnt::Mapper& map, size_t idx) {
    record[out_field] = record["__pkt_key"];
}
