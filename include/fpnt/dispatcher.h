#ifndef _DISPATCHER_H
#define _DISPATCHER_H

#include <fmt/core.h>
#include <fpnt/config.h>
#include <fpnt/loader.h>
#include <fpnt/mapper.h>
#include <fpnt/reader.h>

#include <cstring>
#include <csv.hpp>
#include <filesystem>
// #include <fstream>
#include <nlohmann/json.hpp>
#include <set>
#include <unordered_map>

namespace fpnt {
  void chkOutputDir(const std::filesystem::path& pcap, bool force_remove);
  std::set<std::filesystem::path> get_sorted_pcap_paths(std::string path);
  void chkOutFilepath(const std::filesystem::path& out_filepath);
  std::set<std::string> default_extensions();

  // The custom comparator structure for std::set.
  // It determines the sorting order based on its internal state.
  struct PathComparator {
    bool sort_by_filesize;

    // Constructor to set the sorting preference at creation.
    PathComparator(bool sort_by_size = false) : sort_by_filesize(sort_by_size) {}

    // The comparison operator required by std::set.
    // Must return true if 'a' should come before 'b' in the sorted order.
    bool operator()(const std::filesystem::path& a, const std::filesystem::path& b) const {
      if (sort_by_filesize) {
        // Sorting by file size (Ascending order)
        try {
          // Get file sizes. Assume size is 0 for non-regular files or on error
          // for simpler example code. Robust code would need better error handling.
          uintmax_t size_a
              = std::filesystem::is_regular_file(a) ? std::filesystem::file_size(a) : 0;
          uintmax_t size_b
              = std::filesystem::is_regular_file(b) ? std::filesystem::file_size(b) : 0;

          if (size_a != size_b) {
            return size_a > size_b;  // Sort by size (descending order to avoid head of line blocking issue)
          }
        } catch (const std::filesystem::filesystem_error& e) {
          // Fallback to path name sort on file system error
          // std::cerr << "Filesystem Error: " << e.what() << std::endl;
        }
      }

      // Default sorting: lexicographical (path name) comparison.
      // Used when:
      // 1. Files sizes are equal.
      // 2. sort_by_filesize is false.
      // 3. A filesystem error occurred getting the file size.
      return a.lexically_normal() < b.lexically_normal();
    }
  };

  // Define the type of 'sorted' using the custom comparator.
  using SortedPathSet = std::set<std::filesystem::path, PathComparator>;

  void print_set_details(const SortedPathSet& sorted, const std::string& title);

  class Dispatcher {
  private:
    const nlohmann::json config;
    std::set<std::string> extensions;
    bool force_remove;

    std::string csv_path;  // csv_path must be appeared before '*Reader's, for initialization issue.
    std::string in_path;
    std::string out_path;
    //std::set<std::filesystem::path> sorted;
    SortedPathSet sorted; // key; absolute path
    std::map<std::filesystem::path, std::filesystem::path> relative_path; //output relative path from key

    TSharkCSVReader in_reader;
    // CSVReader reader_outfmt_pkt;
    // CSVReader reader_outfmt_flow;
    // CSVReader reader_outfmt_flowset;
    std::vector<CSVReader> out_readers;
    Loader loader;

    std::filesystem::path cur_abs_path;
    

    // std::pair<size_t, size_t> Dispatcher::chk_get_valid(std::string& from, std::string& to);

  public:
    // during processing, these variables maintains the current position
    // this information can be used for preprocessing functions
    size_t file_idx;  // Note: since sorted_pcap_paths is C++ set, this idx cannot be used for path
                      // access; get_out_filepath() must be used;
    size_t in_pkt_idx;  // v0.3
    // size_t pkt_idx;
    // size_t flow_idx;
    // size_t flowset_idx;
    std::vector<size_t> idxs;                          // v0.3
    std::vector<std::string> g_lvs;                    // v0.3, granularity levels
    std::unordered_map<std::string, size_t> g_lv_idx;  // v0.3, granularity level inverse map

    TSharkMapper in_map;
    // Mapper map_pkt;
    // Mapper map_flow;
    // Mapper map_flowset;
    std::unordered_map<std::string, Mapper> out_maps;  // Mapper will be copied from readers...

    std::vector<nlohmann::json> in_pkts;
    // std::vector<nlohmann::json> out_pkts;
    // std::vector<nlohmann::json> out_flows;
    // std::vector<nlohmann::json> out_flowsets;
    std::unordered_map<std::string, std::unordered_map<std::string, nlohmann::json>>
        out;  // v0.3 out record는 key로만 접근함

    // std::set<std::string> keys_pkt;
    // std::set<std::string> keys_flow;
    // std::set<std::string> keys_flowset;
    std::unordered_map<std::string, std::set<std::string>> out_keys;                       // v0.3
    std::unordered_map<std::string, std::vector<std::string>> out_idx2key;                 // v0.3
    std::unordered_map<std::string, std::unordered_map<std::string, size_t>> out_key2idx;  // v0.3
    std::unordered_map<std::string, std::unordered_map<std::string, std::vector<std::string>>>
        out_child_keys;  // v0.3

    // std::map<std::string, size_t> flow_idx_from_flow; // get_idx(key, "flow")
    // std::map<std::string, std::vector<size_t>> pkt_idxs_from_flow; // get_idxs(key, "flow",
    // "pkt") std::map<std::string, std::vector<size_t>> pkt_idxs_from_flowset; // get_idxs(key,
    // "flowset", "pkt") std::map<std::string, std::vector<std::string>> flow_keys_from_flowset; //
    // get_keys(key, "flowset", "flow")
    size_t get_idx(std::string key, std::string from, std::string to = "eq");              // v0.3
    std::string get_key(std::string key, std::string from, std::string to = "eq");         // v0.3
    std::vector<size_t> get_idxs(std::string key, std::string from, std::string to);       // v0.3
    std::vector<std::string> get_keys(std::string key, std::string from, std::string to);  // v0.3

    nlohmann::json tmp;

    const SortedPathSet& set_sorted_pcap_paths(std::string path);
    const SortedPathSet& get_sorted_pcap_paths() { return this->sorted; };
    const std::filesystem::path get_in_filepath() { return cur_abs_path; };
    const std::filesystem::path get_out_filepath(std::string postfix = "") {
      const std::string output_type = config["output_type"].get<std::string>();
      auto result = out_path / relative_path[cur_abs_path];
      result.replace_extension(postfix + output_type);
      return result;
    };

    size_t counter = 0;  // counter represents the number of child processes to be forked for file
                         // processing so, for each child, counter means file_idx;

    Dispatcher() = delete;
    Dispatcher(const nlohmann::json config,
               std::set<std::string> extensions = default_extensions());

    void dispatch();

    void process_main(const std::filesystem::path abs_path);
    void process_base();
    void process(std::string granularity);
    // void process_pkt();
    // void process_flow();
    // void process_flowset();

    void writer(std::string granularity = "");

    void print_buf_pkt(std::string out_pkt_filepath);

    void print_path_details(const SortedPathSet& sorted, const std::string& title);
  };

};  // namespace fpnt

#endif