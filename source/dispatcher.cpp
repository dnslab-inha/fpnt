#include <fpnt/dispatcher.h>
#include <sys/wait.h>
#include <unistd.h>

#include <set>
#include <thread>

namespace fpnt {
  const unsigned int max_concurrency = std::thread::hardware_concurrency();

  std::set<std::string> default_extensions() {
    std::set<std::string> result;
    result.insert(".pcap");
    result.insert(".pcapng");
    return result;
  }

  Dispatcher::Dispatcher(const nlohmann::json config, std::set<std::string> extensions)
      : config(config),
        extensions(extensions),
        csv_path(config["configcsv_path"].get<std::string>() + "/"),
        input_path(config["input_pcap_path"].get<std::string>()),
        output_path(config["output_path"].get<std::string>()),
        reader_t(csv_path + "input_tshark.csv", config["dfref_path"].get<std::string>()),
        reader_outfmt_pkt(csv_path + "output_pkt.csv"),
        reader_outfmt_flow(csv_path + "output_flow.csv"),
        reader_outfmt_flowset(csv_path + "output_flowset.csv"),
        loader{config["plugins_path"].get<std::string>()},
        map_t(reader_t.read()),
        map_pkt(reader_outfmt_pkt.read(&loader)),
        map_flow(reader_outfmt_flow.read(&loader)),
        map_flowset(reader_outfmt_flowset.read(&loader)) {
    file_idx = -1;
    pkt_idx = -1;
    flow_idx = -1;
    flowset_idx = -1;  // set the processing idxes infinity
    force_remove = config["force_remove"].get<bool>();
    // std::cout << csv_path << std::endl;

    // map_t.print();
    // map_pkt.print();
    // map_flow.print();
    // map_flowset.print();

    Dispatcher** d = (Dispatcher**)loader.getDispatcherPtr();
    *d = this;

    chkOutputDir(output_path, force_remove);

#ifndef NDEBUG
    std::cout << "--- Loader loaded the following plugin functions:" << std::endl;
    loader.printFns();
    std::cout << "---" << std::endl;
#endif

    // sort_paths
    set_sorted_pcap_paths(input_path);
  }

  void Dispatcher::process_main(const std::filesystem::path filepath) {
    // clear the current state to the dispatcher
    file_idx = counter;
    pkt_idx = -1;
    flow_idx = -1;
    flowset_idx = -1;
    in_pkts.clear();    out_pkts.clear();    out_flows.clear();    out_flowsets.clear();
    keys_pkt.clear(); keys_flow.clear(); keys_flowset.clear();
    flow_idx_from_flow.clear(); 
    pkt_idxs_from_flow.clear(); pkt_idxs_from_flowset.clear(); flow_keys_from_flowset.clear();
    tmp.clear();
    cur_filepath = filepath;

    bool ctr_bool = config["log_numbering_concurrency"].get<bool>();
    TSharkOutputReader reader_out_tshark(config, map_t, in_pkts, get_in_filepath(),
                                         ctr_bool ? getpid() : -1);

    reader_out_tshark.read();  // in_pkts will be filled by invoking this function.

    process_pkt();
    process_flow();
    process_flowset();

    

    writer("pkt.");
    writer("flow.");
    writer("flowset.");

    // print_buf_pkt(out_pkt_filepath.c_str());

    // std::cout << "??" << std::endl;
    // std::string a;
    // nlohmann::json b;
    // b["B"] = "";
    // //P_cpy(const std::string &out_field, std::string& option, nlohmann::json& record,
    // fpnt::Mapper& map, size_t idx) std::string d = "P_cpy"; std::string e =
    // "frame.time_epoch"; auto c = loader.getPrepFn(d); c("B", e, b, map_t, 0); std::cout <<
    // "asdasdasdasdasd " << b["B"] << std::endl; std::cout << "dispatch" << this << std::endl;
    // std::cout << "DUMPed solution" << in_pkts[0].dump() << std::endl;

  }

  void Dispatcher::dispatch() {
    size_t no_processes = 0;

    for (auto filepath : sorted) {
      if (config["multiprocessing"] == true) {
        int rc = fork();

        if (rc < 0) {
          std::cout << "fork failed" << std::endl;
          exit(1);
        } else if (rc > 0) {  // parent
          counter++;
          no_processes += 1;
//          std::cout << "Counter: " << no_processes << std::endl;
          if (no_processes > max_concurrency) {
            int wc = wait(NULL);
            if (wc == -1) {
              if (errno != ECHILD) {
                std::cerr << "dispatch: wait() has unusual errno: " << strerror(errno) << std::endl;
              }
            } else {
              no_processes -= 1;
//              std::cout << "Counter: " << no_processes << std::endl;
            }
          }
        } else {  // child
          process_main(filepath);
          sleep(5);
          exit(0);
        }
      } else
        process_main(filepath);
    }

    while (config["multiprocessing"] && no_processes > 0) {
      int wc = wait(NULL);
      if (wc == -1) {
        if (errno != ECHILD) {
          std::cerr << "dispatch: wait() has unusual errno: " << strerror(errno) << std::endl;
        }
      } else {
        no_processes -= 1;
        //std::cout << "Counter: " << no_processes << std::endl;
      }
    }
  }

  void Dispatcher::print_buf_pkt(std::string out_pkt_filepath) {
    for (auto& it : in_pkts) {
      std::cout << "File [" << out_pkt_filepath << "]: ";
      for (auto& col_name : map_t.getFields()) {
        // cout << col_name << endl;
        std::cout << it[col_name].get<std::string>() << "\t";
      }
      std::cout << std::endl;
    }
  }

  void Dispatcher::process_pkt() {
    flow_idx = -1;
    flowset_idx = -1;

    // optimization for prep_fns_opts
    std::vector<std::vector<std::pair<std::string, std::string>>> vec_prep_fns_opts;
    for (auto &out_field: map_pkt.getFields()) {
      auto prep_fns_opts = map_pkt.getPrepFns(out_field);
      vec_prep_fns_opts.push_back(prep_fns_opts);
    }

    auto genKey_pkt = loader.getGenKeyFn(config["genKey_pkt"]);
    auto genKey_flow = loader.getGenKeyFn(config["genKey_flow"]);
    auto genKey_flowset = loader.getGenKeyFn(config["genKey_flowset"]);

    // this loop assumes that one in_pkt == one out_pkt
    // so that after generating keys out pkts are inserted immediately
    for (size_t idx = 0; idx < in_pkts.size(); idx++) {  // for each in_pkt
      pkt_idx = idx;
      // obtain keys for input packet (in_pkt)
      auto flowset_key = genKey_flowset(in_pkts[idx], map_t);
      in_pkts[idx]["flowset_key"] = flowset_key;
      pkt_idxs_from_flowset[flowset_key].push_back(idx);
      auto result = keys_flowset.insert(flowset_key);
      if (result.second) {  // if new flowset key
        nlohmann::json out_flowset;
        out_flowset["__flowset_key"] = flowset_key;
        out_flowsets.push_back(out_flowset);
      }

      auto flow_key = genKey_flow(in_pkts[idx], map_t);
      in_pkts[idx]["flow_key"] = flow_key;
      pkt_idxs_from_flow[flow_key].push_back(idx);
      result = keys_flow.insert(flow_key);
      if (result.second) {  // if new flow key
        flow_keys_from_flowset[flowset_key].push_back(flow_key);
        nlohmann::json out_flow;
        out_flow["__flow_key"] = flow_key;
        out_flow["__flowset_key"] = flowset_key;
        flow_idx_from_flow[flow_key] = out_flows.size();
        out_flows.push_back(out_flow);
      }

      auto pkt_key = genKey_pkt(in_pkts[idx], map_t);
      in_pkts[idx]["pkt_key"] = pkt_key;
      result = keys_pkt.insert(pkt_key);
      if (!result.second) {  // if not new packet key
        // TODO
      }

      // new packet key found!
      nlohmann::json out_pkt;
      out_pkt["__pkt_key"] = pkt_key;
      out_pkt["__flow_key"] = flow_key;
      out_pkt["__flowset_key"] = flowset_key;

      size_t field_idx = 0;
      for (auto &out_field: map_pkt.getFields()) {
        //std::cout << "Field:" << out_field << std::endl;
        //out_pkt[out_field] = "";
        //auto prep_fns_opts = map_pkt.getPrepFns(out_field);
        //std::cout << "Size: " << prep_fns_opts.size() << std::endl;
        //for (auto &[str_fn, option]: prep_fns_opts) {
        for (auto &[str_fn, option]: vec_prep_fns_opts[field_idx]) {
          //std::cout << str_fn << " " << option << std::endl;
          auto prep_fn = loader.getPrepFn(str_fn);
          prep_fn(out_field, option, out_pkt, map_pkt, idx);
        }

        if (out_pkt[out_field].is_null()) {
          out_pkt[out_field] = "";
        }
        field_idx++;
      }

      //std::cout << out_pkt.dump() << std:: endl;

      out_pkts.push_back(out_pkt);
    }

    pkt_idx = -1;
  }

  void Dispatcher::process_flow() {
    pkt_idx = -1;
    flowset_idx = -1;

    // optimization for prep_fns_opts
    std::vector<std::vector<std::pair<std::string, std::string>>> vec_prep_fns_opts;
    for (auto &out_field: map_flow.getFields()) {
      auto prep_fns_opts = map_flow.getPrepFns(out_field);
      vec_prep_fns_opts.push_back(prep_fns_opts);
    }

    for (size_t idx = 0; idx < out_flows.size(); idx++) {  // for each in_pkt
      flow_idx = idx;

      size_t field_idx = 0;
      for (auto &out_field: map_flow.getFields()) {
        for (auto &[str_fn, option]: vec_prep_fns_opts[field_idx]) {
          auto prep_fn = loader.getPrepFn(str_fn);
          prep_fn(out_field, option, out_flows[idx], map_flow, idx);
        }

        if (out_flows[idx][out_field].is_null()) {
          out_flows[idx][out_field] = "";
        }
        field_idx++;
      }
    }

    flow_idx = -1;
  }

  void Dispatcher::process_flowset() {
    pkt_idx = -1;
    flow_idx = -1;

    // optimization for prep_fns_opts
    std::vector<std::vector<std::pair<std::string, std::string>>> vec_prep_fns_opts;
    for (auto &out_field: map_flowset.getFields()) {
      auto prep_fns_opts = map_flowset.getPrepFns(out_field);
      vec_prep_fns_opts.push_back(prep_fns_opts);
    }

    for (size_t idx = 0; idx < out_flowsets.size(); idx++) {  // for each in_pkt
      flowset_idx = idx;

      size_t field_idx = 0;
      for (auto &out_field: map_flowset.getFields()) {
        for (auto &[str_fn, option]: vec_prep_fns_opts[field_idx]) {
          auto prep_fn = loader.getPrepFn(str_fn);
          prep_fn(out_field, option, out_flowsets[idx], map_flowset, idx);
        }

        if (out_flowsets[idx][out_field].is_null()) {
          out_flowsets[idx][out_field] = "";
        }
        field_idx++;
      }
    }

    flowset_idx = -1;
  }


  void Dispatcher::writer(std::string postfix) {
    Mapper* cur_map = nullptr;
    std::vector<nlohmann::json>* buf;

    if (postfix == "") {  // print all in one
      // TODO: 다 합치려면 고려해야 할 것들이 좀 있음
    } else if (postfix == "pkt.") {
      cur_map = &map_pkt;
      buf = &out_pkts;
    } else if (postfix == "flow.") {
      cur_map = &map_flow;
      buf = &out_flows;
    } else if (postfix == "flowset.") {
      cur_map = &map_flowset;
      buf = &out_flowsets;
    }

    chkOutFilepath(get_out_filepath(postfix));

    std::ofstream of(get_out_filepath(postfix));
    auto csv_writer = csv::make_csv_writer(of,false);
    csv_writer << (cur_map->getFields());  // print header line

    //size_t size_fields = cur_map->getFields().size();
    for (auto& row : *buf) {
      std::vector<std::string> row_vector;
      for (auto& field : cur_map->getFields()) {
        //std::cout << "ROW: " << row.dump() << std::endl;
        row_vector.push_back(row[field]);
      }
      csv_writer << row_vector;
    }
  }

  void chkOutFilepath(const std::filesystem::path& out_filepath) {
    auto parent_dir = out_filepath.parent_path();

    auto parent_dir_status = std::filesystem::status(parent_dir);
    if (!std::filesystem::exists(parent_dir_status)
        && std::filesystem::create_directories(parent_dir) == false) {
      std::cerr << "chkOutFilepath: Output pcap's parent directory is not properly created! "
                << parent_dir << std::endl;
      exit(1);
    }
  }

  void chkOutputDir(const std::filesystem::path& pcap, bool force_remove) {
    if (!std::filesystem::exists(pcap)) {
    file_creation:
      std::cout << "chkOutputDir: Output directory '" << pcap << "' is creating..." << std::endl;

      if (std::filesystem::create_directories(pcap) == false) {
        std::cerr << "chkOutputDir: Cannot Create Directory '" << pcap << "'" << std::endl;
        exit(1);
      }
    } else if (std::filesystem::is_regular_file(pcap))  // 존재하며 파일임
    {
      bool remove_result = false;
      if (force_remove) {
        std::cout << "chkOutputDir: Output directory '" << pcap
                  << "' is actually a file... It will be deleted!" << std::endl;
        remove_result = std::filesystem::remove(pcap);
      }

      if (remove_result == false) {
        std::cerr << "chkOutputDir: Cannot Remove File '" << pcap << "'";
        if (!force_remove) std::cerr << "due to force_remove option";
        std::cerr << std::endl;
        exit(1);
      }

      goto file_creation;
    } else if (std::filesystem::is_directory(pcap))  // 디렉토리이고 empty
    {
      // int i = 0;
      auto it = std::filesystem::begin(std::filesystem::directory_iterator(pcap));

      //   for (auto& it: std::filesystem::directory_iterator(pcap)) {
      //     i++;
      //     break;
      //   }

      //   if (i != 0) {  // file exists
      if (it != std::filesystem::end(std::filesystem::directory_iterator(pcap))) {  // file exists
        bool remove_result = false;
        if (force_remove) {
          std::cout << "chkOutputDir: Output directory '" << pcap
                    << "' exists and non-empty... It will be deleted!" << std::endl;
          remove_result = std::filesystem::remove_all(pcap);

          goto file_creation;
        }

        if (remove_result == false) {
          std::cerr << "chkOutputDir: Cannot Remove Output Directory '" << pcap << "'";
          if (!force_remove) std::cerr << "due to force_remove option" << std::endl;
          std::cerr << std::endl;
          exit(1);
        }
      }
    }
    // guarantees pcap is an empty directory
  }

  const std::set<std::filesystem::path>& Dispatcher::set_sorted_pcap_paths(std::string path) {
    std::set<std::filesystem::path> result;

    const std::filesystem::path input_pcap_path{path};

    if (!std::filesystem::exists(input_pcap_path)) {
      std::cerr << "set_sorted_pcap_paths: " << path << " does not exist!" << std::endl;
      exit(1);
    }

    for (auto const& dir_entry : std::filesystem::recursive_directory_iterator{input_pcap_path}) {
      if (dir_entry.is_regular_file()) {
        std::string ext = dir_entry.path().extension();
        if (this->extensions.contains(ext)) {
          result.insert(std::filesystem::relative(dir_entry.path(), input_pcap_path));
        }
      }
    }

    this->sorted = result;

    return this->sorted;
  }
}  // namespace fpnt