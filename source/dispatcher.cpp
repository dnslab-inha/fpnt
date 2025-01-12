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
        in_path(config["input_pcap_path"].get<std::string>()),
        out_path(config["output_path"].get<std::string>()),
        in_reader(csv_path + "input_tshark.csv", config["dfref_path"].get<std::string>()),
        // reader_outfmt_pkt(csv_path + "output_pkt.csv"),
        // reader_outfmt_flow(csv_path + "output_flow.csv"),
        // reader_outfmt_flowset(csv_path + "output_flowset.csv"),
        loader{config["plugins_path"].get<std::string>()}
  // map_pkt(reader_outfmt_pkt.read(&loader)),
  // map_flow(reader_outfmt_flow.read(&loader)),
  // map_flowset(reader_outfmt_flowset.read(&loader))
  {
    file_idx = -1;
    in_pkt_idx = -1;
    // pkt_idx = -1;
    // flow_idx = -1;
    // flowset_idx = -1;  // set the processing idxes infinity

    in_map = TSharkMapper(in_reader.read());

    auto str_granularities = config["granularities"].get<std::string>();
    g_lvs = split(config["granularities"].get<std::string>(), ',');
    idxs.clear();
    // g_lvs.clear();
    // g_lv_idx.clear();
    out.clear();
    out_readers.clear();
    out_maps.clear();
    out_keys.clear();
    out_idx2key.clear();
    out_key2idx.clear();
    out_child_keys.clear();
    for (size_t i = 0; i < g_lvs.size(); i++) {
      g_lv_idx[g_lvs[i]] = i;
      idxs.push_back(-1);
      out_readers.push_back(CSVReader(csv_path + "output_" + g_lvs[i] + ".csv"));
      out_maps[g_lvs[i]] = out_readers[i].read(&loader);
      out_keys[g_lvs[i]] = std::set<std::string>();
    }

    force_remove = config["force_remove"].get<bool>();
    // std::cout << csv_path << std::endl;

    // in_map.print();
    // map_pkt.print();
    // map_flow.print();
    // map_flowset.print();

    Dispatcher** d = (Dispatcher**)loader.getDispatcherPtr();
    *d = this;

    chkOutputDir(out_path, force_remove);

#ifndef NDEBUG
    std::cout << "--- Loader loaded the following plugin functions:" << std::endl;
    loader.printFns();
    std::cout << "---" << std::endl;
#endif

    // sort_paths
    set_sorted_pcap_paths(in_path);
  }

  void Dispatcher::process_main(const std::filesystem::path filepath) {
    // clear the current state to the dispatcher
    file_idx = counter;
    in_pkt_idx = -1;
    in_pkts.clear();

    // TO BE DELETED
    // pkt_idx = -1;
    // flow_idx = -1;
    // flowset_idx = -1;
    // out_pkts.clear();    out_flows.clear();    out_flowsets.clear();
    // keys_pkt.clear(); keys_flow.clear(); keys_flowset.clear();
    // flow_idx_from_flow.clear();
    // pkt_idxs_from_flow.clear(); pkt_idxs_from_flowset.clear(); flow_keys_from_flowset.clear();

    idxs.clear();
    // g_lvs.clear();
    // g_lv_idx.clear();
    out.clear();
    out_readers.clear();
    out_maps.clear();
    out_keys.clear();
    out_idx2key.clear();
    out_key2idx.clear();
    out_child_keys.clear();
    for (size_t i = 0; i < g_lvs.size(); i++) {
      idxs.push_back(-1);
      out_readers.push_back(CSVReader(csv_path + "output_" + g_lvs[i] + ".csv"));
      out_maps[g_lvs[i]] = out_readers[i].read(&loader);
      out_keys[g_lvs[i]] = std::set<std::string>();
    }

    tmp.clear();
    cur_filepath = filepath;

    bool ctr_bool = config["log_numbering_concurrency"].get<bool>();
    TSharkOutputReader reader_out_tshark(config, in_map, in_pkts, get_in_filepath(),
                                         ctr_bool ? getpid() : -1);

    reader_out_tshark.read();  // in_pkts will be filled by invoking this function.

    process_keygen();
    for (size_t i = 0; i < g_lvs.size(); i++) {
      process(g_lvs[i]);
    }
    // process_pkt();
    // process_flow();
    // process_flowset();

    for (size_t i = 0; i < g_lvs.size(); i++) {
      writer(g_lvs[i]);
    }

    // writer("pkt.");
    // writer("flow.");
    // writer("flowset.");

    // print_buf_pkt(out_pkt_filepath.c_str());

    // std::cout << "??" << std::endl;
    // std::string a;
    // nlohmann::json b;
    // b["B"] = "";
    // //P_cpy(const std::string &out_field, std::string& option, nlohmann::json& record,
    // fpnt::Mapper& map, size_t idx) std::string d = "P_cpy"; std::string e =
    // "frame.time_epoch"; auto c = loader.getPrepFn(d); c("B", e, b, in_map, 0); std::cout <<
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
        // std::cout << "Counter: " << no_processes << std::endl;
      }
    }
  }

  void Dispatcher::print_buf_pkt(std::string out_pkt_filepath) {
    for (auto& it : in_pkts) {
      std::cout << "File [" << out_pkt_filepath << "]: ";
      for (auto& col_name : in_map.getFields()) {
        // cout << col_name << endl;
        std::cout << it[col_name].get<std::string>() << "\t";
      }
      std::cout << std::endl;
    }
  }

  void Dispatcher::process_keygen() {
    // 초기화
    in_pkt_idx = -1;
    for (size_t i = 0; i < g_lvs.size(); i++) {
      idxs[i] = -1;
    }

    // 키 생성 함수 준비
    std::vector<fnptr_genKeyFn> genKeyFns;
    for (size_t i = 0; i < g_lvs.size(); i++) {
      genKeyFns.push_back(loader.getGenKeyFn(config["genKey_" + g_lvs[i]]));
    }

    std::cout << "in_pkts_size: " << in_pkts.size() << std::endl;

    // this loop assumes that one in_pkt == one out_pkt
    // so that after generating keys out pkts are inserted immediately
    for (size_t idx = 0; idx < in_pkts.size(); idx++) {  // for each in_pkt
      in_pkt_idx = idx;
      
      std::vector<std::string> keys(g_lvs.size());
      std::vector<std::string> idxs(g_lvs.size());
      for (size_t i = 0; i < g_lvs.size(); i++) {

        size_t cnt = (g_lvs.size()-1) - i; // 최상위 수준에서 아래로 탐색해야 함
        keys[cnt] = genKeyFns[cnt](in_pkts[idx], g_lvs[cnt], keys[cnt]);

        in_pkts[idx][g_lvs[cnt] + "_key"] = keys[cnt]; // in_pkts는 idx와 cnt를 이용해 키를 넣기만 하면 됨

        size_t cnt_idx = out_keys[g_lvs[cnt]].size();         // true일 경우 out의 idx
        auto result = out_keys[g_lvs[cnt]].insert(keys[cnt]); // 키 삽입 시도

        if (result.second) { // 새 키 삽입인 경우 대응하는 레코드 객체를 생성
            nlohmann::json out_obj;
            out_obj["__in_idx"] = idx;
            //std::cout << "__in_idx: " << idx << " g_lvs[cnt] " << g_lvs[cnt] << " " << keys[cnt] << " idx2keysize " << out_idx2key[g_lvs[cnt]].size() << " key2idxsize " << out_key2idx[g_lvs[cnt]].size() << std::endl;
            out[g_lvs[cnt]][keys[cnt]] = out_obj;
            //out_idx2key[g_lvs[cnt]][cnt_idx] = keys[cnt];
            out_idx2key[g_lvs[cnt]].push_back(keys[cnt]);
            out_key2idx[g_lvs[cnt]][keys[cnt]] = cnt_idx;

            for (size_t j = cnt; j < g_lvs.size(); j++) {
                out[g_lvs[j]][keys[j]]["__" + g_lvs[cnt] + "_key"] = keys[cnt];
                out[g_lvs[j]][keys[j]]["__" + g_lvs[cnt] + "_idx"] = cnt_idx; // =idxs[cnt]

                if (j == cnt + 1) { // parent인 경우에 한해서
                  out_child_keys[g_lvs[j]][keys[j]].push_back(keys[cnt]);
                }
            }
        } else {            // 기존에 있는 키라면, cnt_idx를 해당 out 레코드 객체를 가리킴
            cnt_idx = out_key2idx[g_lvs[cnt]][keys[cnt]];
        }
        idxs[cnt] = cnt_idx;
        // keys[cnt]와 idxs[cnt]에 적절한 값이 삽입된 상황임
      }
    }
  }

  void Dispatcher::process(std::string granularity) {
    // 현재 granularity를 제외하고 idx 초기화
    size_t ptr_g = -1;
    for (size_t i = 0; i < g_lvs.size(); i++) {
      idxs[i] = -1;
      if (g_lvs[i] == granularity) ptr_g = i;
    }

    auto out_fields = out_maps[granularity].getFields();

    // optimization for prep_fns_opts
    std::vector<std::vector<std::pair<std::string, std::string>>> vec_prep_fns_opts;
    for (auto& out_field : out_fields) {
      auto prep_fns_opts = out_maps[granularity].getPrepFns(out_field);
      vec_prep_fns_opts.push_back(prep_fns_opts);
    }

    for (size_t idx = 0; idx < out_idx2key[granularity].size(); idx++) { 
      idxs[ptr_g] = idx;

      const std::string& cnt_out_key = out_idx2key[granularity][idx];
      //const size_t cnt_out_idx = out_key2idx[granularity][cnt_out_key];
      nlohmann::json* record_ptr = &out[granularity][cnt_out_key];

      size_t field_idx = 0;
      for (auto& out_field : out_fields) {
        for (auto& [str_fn, option] : vec_prep_fns_opts[field_idx]) {
          auto prep_fn = loader.getPrepFn(str_fn);
          prep_fn(option, *record_ptr, granularity, cnt_out_key, out_field);
        }

        if ((*record_ptr)[out_field].is_null()) {
          (*record_ptr)[out_field] = "";
        }
        field_idx++;
      }
    }

    idxs[ptr_g] = -1;
  }

  /*
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
        auto flowset_key = genKey_flowset(in_pkts[idx], in_map);
        in_pkts[idx]["flowset_key"] = flowset_key;
        pkt_idxs_from_flowset[flowset_key].push_back(idx);
        auto result = keys_flowset.insert(flowset_key);
        if (result.second) {  // if new flowset key
          nlohmann::json out_flowset;
          out_flowset["__flowset_key"] = flowset_key;
          out_flowsets.push_back(out_flowset);
        }

        auto flow_key = genKey_flow(in_pkts[idx], in_map);
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

        auto pkt_key = genKey_pkt(in_pkts[idx], in_map);
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

  */
  void Dispatcher::writer(std::string granularity) {
    Mapper* cur_map = nullptr;
    //std::vector<nlohmann::json>* buf;
    std::string postfix = granularity + ".";

    if (granularity == "") {  // print all in one
      // TODO: 다 합치려면 고려해야 할 것들이 좀 있음
    } else {
      cur_map = &out_maps[granularity];
    }

    // if (postfix == "") {  // print all in one
    //   // TODO: 다 합치려면 고려해야 할 것들이 좀 있음
    // } else if (postfix == "pkt.") {
    //   cur_map = &map_pkt;
    //   buf = &out_pkts;
    // } else if (postfix == "flow.") {
    //   cur_map = &map_flow;
    //   buf = &out_flows;
    // } else if (postfix == "flowset.") {
    //   cur_map = &map_flowset;
    //   buf = &out_flowsets;
    // }

    chkOutFilepath(get_out_filepath(postfix));

    std::ofstream of(get_out_filepath(postfix));
    auto csv_writer = csv::make_csv_writer(of, false);
    csv_writer << (cur_map->getFields());  // print header line

    // size_t size_fields = cur_map->getFields().size();
    for (size_t idx = 0; idx < out_idx2key[granularity].size(); idx++) {
      const std::string& cnt_out_key = out_idx2key[granularity][idx];
      auto& row = out[granularity][cnt_out_key];

      std::vector<std::string> row_vector;
      for (auto& field : cur_map->getFields()) {
        // std::cout << "ROW: " << row.dump() << std::endl;
        row_vector.push_back(row[field]);
      }
      csv_writer << row_vector;
    }
  }

  // std::pair<size_t, size_t> Dispatcher::chk_get_valid(std::string& from, std::string& to) {
  //   bool valid = false;
  //   for (size_t i = 0; i < g_lvs.size(); i++) {
  //     if (from == g_lvs[i]) {
  //       for (size_t j = i; j < g_lvs.size(); j++) {
  //         if (to == g_lvs[j]) {
  //           valid = true;
  //           return std::make_pair(i, j);
  //         }
  //       }
  //     }
  //   }

  //   if (!valid) {
  //         std::cerr << "get_* input is invalid!" << std::endl;
  //         exit(1);
  //   }
  // }

  /*
   */
  size_t Dispatcher::get_idx(std::string key, std::string from, std::string to) {  // v0.3
    nlohmann::json *cnt_obj = &out[from][key];
    if (to == "eq" || from == to) {      
      return (*cnt_obj)["__"+to+"_idx"].get<size_t>();
    }

    //chk_get_valid(from, to); 안 써도 됨
    if (g_lv_idx[from] > g_lv_idx[to]) {
      std::cerr << "please use get_idxs to access lower granuality records!" << std::endl;
      exit(1);
    }

    // now g_lv_idx[from] < g_lv_idx[to]
    return (*cnt_obj)["__"+to+"_idx"].get<size_t>();
  }

  /*
   */
  std::string Dispatcher::get_key(std::string key, std::string from, std::string to) {  // v0.3
    nlohmann::json *cnt_obj = &out[from][key];
    if (to == "eq" || from == to) {      
      return (*cnt_obj)["__"+to+"_key"].get<std::string>();
    }

    //chk_get_valid(from, to); 안 써도 됨
    if (g_lv_idx[from] > g_lv_idx[to]) {
      std::cerr << "please use get_idxs to access lower granuality records!" << std::endl;
      exit(1);
    }

    // now g_lv_idx[from] < g_lv_idx[to]
    return (*cnt_obj)["__"+to+"_key"].get<std::string>();
  }

  std::vector<size_t> Dispatcher::get_idxs(std::string key, std::string from,
                                           std::string to) {  // v0.3
    if (g_lv_idx[from] <= g_lv_idx[to]) {
      std::cerr << "please use get_idx to access higher granuality records!" << std::endl;
      exit(1);
    }

    // g_lv_idx[from] > g_lv_idx[to]
    std::vector<size_t> result;
    std::vector<std::string> cnt_child_keys = out_child_keys[from][key];
    for (auto &x: cnt_child_keys) {
      if (g_lv_idx[from] == g_lv_idx[to] + 1) {
        result.push_back(out_key2idx[to][x]);
      } else {
        std::vector<std::size_t> child_result = get_idxs(x, g_lvs[g_lv_idx[from] - 1], to);
        result.insert( result.end(), child_result.begin(), child_result.end());
      }
    }

    return result;
  }

  std::vector<std::string> Dispatcher::get_keys(std::string key, std::string from,
                                                std::string to) {  // v0.3
    if (g_lv_idx[from] <= g_lv_idx[to]) {
      std::cerr << "please use get_idx to access higher granuality records!" << std::endl;
      exit(1);
    }

    // g_lv_idx[from] > g_lv_idx[to]
    std::vector<std::string> result;
    std::vector<std::string> cnt_child_keys = out_child_keys[from][key];
    for (auto &x: cnt_child_keys) {
      if (g_lv_idx[from] == g_lv_idx[to] + 1) {
        result.push_back(x);
      } else {
        std::vector<std::string> child_result = get_keys(x, g_lvs[g_lv_idx[from] - 1], to);
        result.insert( result.end(), child_result.begin(), child_result.end());
      }
    }
    return result;
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