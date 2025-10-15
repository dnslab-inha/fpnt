#include <fpnt/dispatcher.h>
#include <sys/wait.h>
#include <unistd.h>

#include <set>
#include <thread>

#include <csignal>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <algorithm>

namespace fpnt {
  unsigned int max_concurrency = std::thread::hardware_concurrency();
  bool multiprocessing = false;
  std::set<pid_t> child_processes;

  std::set<std::string> default_extensions() {
    std::set<std::string> result;
    result.insert(".pcap");
    result.insert(".pcapng");
    return result;
  }

  void signal_handler(int signum) {
    //std::cout << "Signal Handler multiprocessing" << multiprocessing << std::endl;
    if (multiprocessing) {
      
      for (pid_t pid : child_processes) {
          std::cout << "Killing " << pid << "..." << std::endl;
          kill(pid, SIGTERM);
          waitpid(pid, nullptr, 0); // Wait for the child process to terminate
      }
      
      exit(signum);
    }
  }

  Dispatcher::Dispatcher(const nlohmann::json config, std::set<std::string> extensions)
      : config(config),
        extensions(extensions),
        csv_path(config["configcsv_path"].get<std::string>() + "/"),
        in_path(config["input_pcap_path"].get<std::string>()),
        out_path(config["output_path"].get<std::string>()),
        in_reader(config["tshark_path"].get<std::string>(), csv_path + "input_tshark.csv", config["dfref_path"].get<std::string>()),
        loader{config["plugins_path"].get<std::string>()}
  {
    file_idx = -1;
    in_pkt_idx = -1;
    in_map = TSharkMapper(in_reader.read());

    auto str_granularities = config["granularities"].get<std::string>();
    g_lvs = split(config["granularities"].get<std::string>(), ',');
    idxs.clear();
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

    idxs.clear();
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

    process_base();
    for (size_t i = 0; i < g_lvs.size(); i++) {
      process(g_lvs[i]);
    }

    for (size_t i = 0; i < g_lvs.size(); i++) {
      writer(g_lvs[i]);
    }

    // print_buf_pkt(out_pkt_filepath.c_str());
  }

  void Dispatcher::dispatch() {

    try {
      multiprocessing = config.at("multiprocessing").get<bool>();
    } catch (nlohmann::json::basic_json::out_of_range& e) {
      multiprocessing = false;
    }

    if (multiprocessing) {
      //std::cout << "signal registered!" << std::endl;
      signal(SIGINT, signal_handler);
    }

    try {  // https://json.nlohmann.me/features/element_access/checked_access/#notes
      int temp_max_concurrency = config.at("max_concurrency").get<int>();
      if (temp_max_concurrency > 0) {
        max_concurrency = temp_max_concurrency;
        std::cout << "max_concurrency: " << max_concurrency << std::endl;
      }
    } catch (nlohmann::json::basic_json::out_of_range& e) {
      // Do Nothing
    }


    for (auto filepath : sorted) {
      if (multiprocessing == true) {
        int rc = fork();

        if (rc < 0) {
          std::cout << "fork failed" << std::endl;
          exit(1);
        } else if (rc > 0) {  // parent
          counter++;
          child_processes.insert(rc);
          //          std::cout << "Counter: " << no_processes << std::endl;
          if (child_processes.size() >= max_concurrency - 1) {
            int wc = wait(NULL);
            if (wc == -1) {
              if (errno != ECHILD) {
                std::cerr << "dispatch: wait() has unusual errno: " << strerror(errno) << std::endl;
              }
            } else {
              child_processes.erase(wc);
              //              std::cout << "Counter: " << no_processes << std::endl;
            }
          }
        } else {  // child
          std::cout << "child" << std::endl;
          process_main(filepath);
          sleep(5);
          exit(0);
        }
      } else
        process_main(filepath);
    }

    //std::cout << "parent multiprocessing no_processes " << multiprocessing << " " << child_processes.size() << std::endl;

    std::vector<pid_t> to_be_erased;
    for(auto pid : child_processes) {
      int wc = waitpid(pid, nullptr, 0);
      if (wc == -1) {
        std::cerr << "dispatch: wait() has unusual errno: " << strerror(errno) << std::endl;
        exit(1);
      } else {
        //std::cout << "pid " << wc << "is terminated." << std::endl;
        to_be_erased.push_back(pid);
        // std::cout << "Counter: " << no_processes << std::endl;
      }
    }
    for(auto pid: to_be_erased) {
      child_processes.erase(pid);
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

  void Dispatcher::process_base() {
    // initialization
    in_pkt_idx = -1;
    for (size_t i = 0; i < g_lvs.size(); i++) {
      idxs[i] = -1;
    }

    // preparation of key generation
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

        size_t cnt = (g_lvs.size()-1) - i; // iterate from the top (the most grouped) granularity to the bottom
        keys[cnt] = genKeyFns[cnt](in_pkts[idx], g_lvs[cnt], keys[cnt]);

        in_pkts[idx][g_lvs[cnt] + "_key"] = keys[cnt]; // inject the generated key to in_pkts

        size_t cnt_idx = out_keys[g_lvs[cnt]].size();
        auto result = out_keys[g_lvs[cnt]].insert(keys[cnt]); // inject the generated key to out_keys

        if (result.second) { // create a record object if a new key is injected to out_keys
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

                if (j == cnt + 1) { // in case of parent
                  out_child_keys[g_lvs[j]][keys[j]].push_back(keys[cnt]);
                }
            }
        } else {            // if it is an existing key, cnt_idx points to the corresponding out record object
            cnt_idx = out_key2idx[g_lvs[cnt]][keys[cnt]];
        }
        idxs[cnt] = cnt_idx;
        // new keys[cnt] idxs[cnt] have appropriate values
      }
    }
  }

  void Dispatcher::process(std::string granularity) {
    // idx initialization except the current 'granularity'
    size_t ptr_g = -1;
    for (size_t i = 0; i < g_lvs.size(); i++) {
      idxs[i] = -1;
      if (g_lvs[i] == granularity) ptr_g = i;
    }

    auto out_fields = out_maps[granularity].getFields();

    // optimization for prep_fns_opts; more optimization is needed
    std::vector<std::vector<std::pair<std::string, std::string>>> vec_prep_fns_opts;
    for (auto& out_field : out_fields) {
      auto prep_fns_opts = out_maps[granularity].getPrepFns(out_field);
      vec_prep_fns_opts.push_back(prep_fns_opts);
    }

    std::cout << "granuality: " << granularity << std::endl;

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

      if (idx % 1000000 == 0)
        std::cout << "idx: " << idx << std::endl;
    }

    idxs[ptr_g] = -1;
  }

  void Dispatcher::writer(std::string granularity) {
    Mapper* cur_map = nullptr;
    std::string postfix = granularity + ".";

    if (granularity == "") {  
      // TODO: print all in one
    } else {
      cur_map = &out_maps[granularity];
    }

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

  size_t Dispatcher::get_idx(std::string key, std::string from, std::string to) {  // v0.3
    nlohmann::json *cnt_obj = &out[from][key];
    if (to == "eq" || from == to) {      
      return (*cnt_obj)["__"+to+"_idx"].get<size_t>();
    }

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
    } else if (std::filesystem::is_regular_file(pcap))  // exists and it is a file
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
    } else if (std::filesystem::is_directory(pcap))  // it is a directory and empty
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