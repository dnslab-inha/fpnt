#ifndef _DISPATCHER_H
#define _DISPATCHER_H

#include <fmt/core.h>
#include <fpnt/config.h>
#include <fpnt/loader.h>
#include <fpnt/reader.h>
#include <fpnt/mapper.h>

#include <cstring>
#include <csv.hpp>
#include <filesystem>
//#include <fstream>
#include <nlohmann/json.hpp>
#include <set>

namespace fpnt {
  void chkOutputDir(const std::filesystem::path& pcap, bool force_remove);
  std::set<std::filesystem::path> get_sorted_pcap_paths(std::string path);
  void chkOutFilepath(const std::filesystem::path& out_filepath);
  std::set<std::string> default_extensions();

  class Dispatcher {
  private:
    const nlohmann::json config;
    std::set<std::string> extensions;
    bool force_remove;

    std::string csv_path;  // csv_path must be appeared before '*Reader's, for initialization issue.
    std::string input_path;
    std::string output_path;
    std::set<std::filesystem::path> sorted;

    TSharkCSVReader reader_t;
    CSVReader reader_outfmt_pkt;
    CSVReader reader_outfmt_flow;
    CSVReader reader_outfmt_flowset;
    Loader loader;

    std::filesystem::path cur_filepath;
    
  public:
    // during processing, these variables maintains the current position
    // this information can be used for preprocessing functions
    size_t file_idx; // Note: since sorted_pcap_paths is C++ set, this idx cannot be used for path access; get_out_filepath() must be used;
    size_t pkt_idx;
    size_t flow_idx;
    size_t flowset_idx;

    TSharkMapper map_t;
    Mapper map_pkt;
    Mapper map_flow;
    Mapper map_flowset;

    std::vector<nlohmann::json> in_pkts;
    std::vector<nlohmann::json> out_pkts;
    std::vector<nlohmann::json> out_flows;
    std::vector<nlohmann::json> out_flowsets;

    std::set<std::string> keys_pkt;
    std::set<std::string> keys_flow;
    std::set<std::string> keys_flowset;
    std::map<std::string, std::vector<size_t>> pkt_idxs_from_flow;
    std::map<std::string, std::vector<size_t>> pkt_idxs_from_flowset;
    std::map<std::string, std::vector<std::string>> flow_keys_from_flowset;

    nlohmann::json tmp;

    const std::set<std::filesystem::path>& set_sorted_pcap_paths(std::string path);
    const std::set<std::filesystem::path>& get_sorted_pcap_paths() { return this->sorted; };
    const std::filesystem::path get_in_filepath() { return input_path / cur_filepath; };
    const std::filesystem::path get_out_filepath(std::string postfix = "") { 
      const std::string output_type = config["output_type"].get<std::string>();
      auto result = output_path / cur_filepath;
      result.replace_extension(postfix + output_type);
      return result; };

    size_t counter = 0; // counter represents the number of child processes to be forked for file processing
                        // so, for each child, counter means file_idx;

    Dispatcher() = delete;
    Dispatcher(const nlohmann::json config, std::set<std::string> extensions = default_extensions());

    void dispatch();

    void process_main(const std::filesystem::path filepath);
    void process_pkt();
    void process_flow();
    void process_flowset();

    void writer(std::string postfix = "");

    void print_buf_pkt(std::string out_pkt_filepath);
  };


};  // namespace fpnt

#endif