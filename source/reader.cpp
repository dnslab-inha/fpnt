#include <fpnt/reader.h>

namespace fpnt {

  csv::CSVFormat tshark_csv_fmt(std::vector<std::string> fields) {
    csv::CSVFormat result;
    result.delimiter('\t').quote(false).column_names(fields);
    return result;
  }

  csv::CSVFormat default_CSVFormat() {
    csv::CSVFormat format;
    format.quote(true).delimiter(',').header_row(0);
    return format;
  }

  void parseVer(const std::string& version, int& x, int& y, int& z) {
    std::stringstream ss(version);
    char dot;
    ss >> x >> dot >> y >> dot >> z;
  }

  void verValid(std::string& field, std::string& name, std::string& ver, int a, int b, int c) {
    int x1, y1, z1;
    int x2, y2, z2;
    char temp;
    std::stringstream ss(ver);
    ss >> x1 >> temp >> y1 >> temp >> z1 >> temp >> temp >> temp >> temp >> x2 >> temp >> y2 >> temp >> z2;

    if ((a > x1 || (a == x1 && (b > y1 || (b == y1 && c >= z1)))) && 
        (a < x2 || (a == x2 && (b < y2 || (b == y2 && c <= z2))))) {
        return;
    }
    
    std::cout << "tshark Version Validation is failed!" << std::endl;
    std::cout << field << "(" << name << ")" << "'s Version Range is " << ver 
    << " but the current tshark version is " << a << "." << b << "." << c << std::endl;

    if (a > x2 || (a == x2 && (b > y2 || (b == y2 && c > z2)))) {
      std::cout << "In this case, display filer reference can be outdated so fpnt will not be terminated." << std::endl;
      return;
    }
    
    exit(1);
  }

  Mapper& CSVReader::read(Loader* loader) {
    csv::CSVReader internal_reader(path, format);
//    std::cout << "READ: " << path << std::endl;
    size_t counter = 0;
    for (auto& row : internal_reader) {
      counter++;
      // field,name,preprocess_fns,options
      std::string name = "", field = "", preprocess_fns_str = "", options = "";
      try {
        name = row["name"].get<std::string>();
      } catch (std::runtime_error& e) {
      }
      try {
        field = row["field"].get<std::string>();
      } catch (std::runtime_error& e) {
      }
      try {
        preprocess_fns_str = row["preprocess_fns"].get<std::string>();
      } catch (std::runtime_error& e) {
      }
      try {
        options = row["options"].get<std::string>();
      } catch (std::runtime_error& e) {
      }

      trim(name);
      trim(field);
      trim(preprocess_fns_str);
      trim(options);
      std::vector<char> quote_chars{'\"', '\''};
      for (auto q: quote_chars)
        if(name[0] == q ||field[0] == q || preprocess_fns_str[0] == q) { // we allow option field can have \' or \"
          std::cerr << "CSVReader: quote_char is remained; malformed csv files for our internal CSV reader; maybe helpful to remove whitespaces between columns" << std::endl;
          exit(1);
        }

      if (field == "") {  // field must be available in the csv file
        std::cerr << "reader_csv_input_tshark: ";
        std::cout << counter << "-th row's field in csv file " << path << " is empty!" << std::endl;
        exit(1);
      }

      if (map[field] != (size_t)-1) {  // field must be unique
        std::cerr << "reader_csv_output_pkt: ";
        std::cout << counter << "-th row's field (" << field << ") in csv file " << path
                  << " is not unique!" << std::endl;
        exit(1);
      }

      // we allow name can be omitted, then field will be used as the name
      if (name == "") name = field;

      // Now, we have unempty name
      map.addField(field, name, "", "");  // TODO: we do not use desc and type in this version.
                                          // maybe these fields can be used

      map.setPrepFns(field, preprocess_fns_str, options);
    }

    if (loader != nullptr) {
      // TODO: Validate!
      auto fields = map.getFields();
      for (auto& field : fields) {
        auto prep_fn_list = map.getPrepFns(field);
        for (auto& [fn, opt] : prep_fn_list) {
          loader->validate(fn);
        }
      }
    }

    return map;
  };

  TSharkMapper& TSharkCSVReader::read(Loader* loader) {
    std::string line;
    bool first = true;
    bool version_validation = true;
    while(std::getline(in, line)) {
      if (first) {
        first = false;
        size_t pos = line.find_last_of(" ");
        if (pos == std::string::npos) {
          std::cout << "tshark does not have a proper version string. version validation will be offed." << std::endl;
          version_validation = false;
          break;
        }
        version = line.substr(pos + 1);
        parseVer(version, major, minor, patch);
      }
    }


    csv::CSVReader internal_reader(path, format);
//    std::cout << "READ: " << path << std::endl;
    std::unordered_map<std::string, std::vector<std::string> > dfref_dirs;

    for (auto const& dir_entry : std::filesystem::directory_iterator{dfref_path}) {
      if (std::filesystem::is_directory(dir_entry.symlink_status())) {
        std::string dirname = std::filesystem::relative(dir_entry, dfref_path);
        if (dirname.length() == 1) {
          dfref_dirs.insert({dirname, std::vector<std::string>()});
        }
      }
    }

    size_t counter = 0;

    for (auto& row : internal_reader) {
      counter++;
      auto name = row["name"].get<std::string>();
      auto field = row["tshark_displayfilter_field"].get<std::string>();
      trim(name);
      trim(field);

      if (field == "") {  // field must be available in the csv file
        std::cerr << "reader_csv_input_tshark: ";
        std::cout << counter << "-th row's tshark display filter field in csv file " << path
                  << " is empty!" << std::endl;
        exit(1);
      }

      if (map[field] != (size_t)-1) {  // field must be unique
        std::cerr << "reader_csv_input_tshark: ";
        std::cout << counter << "-th row's tshark display filter field (" << field
                  << ") in csv file " << path << " is not unique!" << std::endl;
        exit(1);
      }

      // hereafter, field exists and is unique
      // name can be empty so we need to fill name
      // now we need to find desc, type, ver

      // name이 빈 경우를 채우고 나머지 속성에 대한 정보를 구축함
      // 주의: dfref 특성 상 locality가 상당히 높음

      std::string first_char = std::to_string(field[0]);

      if (!dfref_dirs.contains(first_char)) {  // first visit // C++20
        std::string dir_entry = dfref_path + "/" + field[0];
        const std::filesystem::path dfref_curr{dir_entry};

        for (auto const& dir_entry : std::filesystem::directory_iterator{dfref_curr}) {
          if (std::filesystem::is_regular_file(dir_entry.symlink_status())) {
            std::string filename = std::filesystem::relative(dir_entry, dfref_curr);
            dfref_dirs[std::to_string(field[0])].push_back(filename);
          }
        }
      }

      // directory hierarichy assumption: "dfref" / field[0] / filename

      // searching algorithm:
      // (1) take the prefix from row["tshark_displayfilter_field"]
      // (2) iterate dfref_dirs[to_string(field[0])] and filter html files with the prefix
      // (3) brute-force search; if failed, program will be terminated.

      std::string prefix = field.substr(0, field.find("."));  // (1)
      const std::string leftstr = "id=\"" + field + "\"";
      const std::string rightstr = "</tr>";

      bool found = false;
      std::string found_string = "";
      for (auto const& filename : dfref_dirs[std::to_string(field[0])]) {
        const std::filesystem::path path_entry{dfref_path + "/" + field[0] + "/" + filename};

        if (filename.substr(0, prefix.length()).find(prefix) == std::string::npos) continue;

        std::ifstream i(path_entry);
        i.imbue(std::locale("en_US.UTF8"));  // we assume that wireshark display filter reference
                                             // will be offered as a UTF8 document.
        // 가정: getline으로 <tr id=...을 읽어오고, 4096 바이트면 </tr>을 포함한 한 줄을 읽을 수
        // 있다고 가정
        std::size_t l, r;
        for (std::string line; std::getline(i, line);) {
          if ((l = line.find(leftstr)) != std::string::npos) {               // <tr id=... found
            if ((r = line.substr(l).find(rightstr)) != std::string::npos) {  // </tr> found
              found = true;
              found_string = line.substr(
                  l, r);  // r이 line.substr(l)의 결과고, size_t이기 때문에... r-l이 아니라 r임
              break;
            } else {
              std::cerr << "reader_csv_input_tshark: found <tr " << leftstr
                        << "> but failed to find </tr>" << std::endl;
              exit(1);
            }
          }
        }

        if (found) break;
      }

      if (!found) {
        std::cerr << "reader_csv_input_tshark: not found <tr " << leftstr << "> for all files!!"
                  << std::endl;
        exit(1);
      }

      std::string desc, type, ver;

      // found_string은 </td><td>로 시작하는 세 개의 열을 가지고 있으며, 각 열을 추출
      for (int i = 0; i < 3; i++) {
        std::size_t l = found_string.find("</td><td>");
        std::size_t r = found_string.substr(l + 5).find("</td>");
        std::string x = found_string.substr(l + 5 + 4, r - 4);
        found_string = found_string.substr(l + 5 + r);
        switch (i) {
          case 0:  // Description
            desc = x;
            if (name == "") name = x;
            break;
          case 1:  // Type
            type = x;
            break;

          case 2:  // Versions
            ver = x;
            break;
        }
      }
      
      if (version_validation) {
        verValid(field, name, ver, major, minor, patch);
      }

      // Now, we have unempty name
      map.addField(field, name, desc, type, ver);
    }

    if (loader != nullptr) {
      // TODO: Validate!
      auto fields = map.getFields();
      for (auto& field : fields) {
        auto prep_fn_list = map.getPrepFns(field);
        for (auto& [fn, opt] : prep_fn_list) {
          loader->validate(fn);
        }
      }
    }

    return map;
  };

  TSharkMapper& TSharkOutputReader::read(Loader* loader) {
    if (loader != nullptr) {
      std::cerr << "TSharkMapper::read: loader must not be used!" << std::endl;
      exit(1);
    }

    std::string line;
    char c = in.get();
    if (c == std::char_traits<char>::eof()) {  // if tshark silently terminated
      rangBerr("reader: tshark is terminated. check error log"
                   + config["fpnt_tshark_error_log"].get<std::string>(),
               rang::fg::red);
      in.close();
      exit(1);
    } else
      in.unget();

    size_t no_pkts = 0;
    size_t early_stop_pkts = config["early_stop_pkts"].get<size_t>();

    // technical note: CSVParser supports inputstream read but there are two reasons not to use
    // the function even though this approach may degrade its performance: Reason 1: CSVParser
    // seems not to correctly read pstream, a inherited class of inputsteram. Reason 2: We need to
    // implement early stop, so that line-by-line read is essential.
    while (std::getline(in, line)) {
      if (no_pkts >= early_stop_pkts) {  // if early_stop_pkts == -1, this early stop
                                                  // function does not work.
        rangout(fmt::format("splitter: early_stopped {} in_pkts / {} in_pkts", no_pkts,
                            early_stop_pkts),
                rang::fg::blue);
        in.close();
        break;
      }

      auto lines_csv = csv::parse(line, tshark_input_format);

      // with very very high probability, lines_csv has only one element.
      // So it is better not to optimize this code.
      for (auto& row : lines_csv) {
        nlohmann::json row_json;
        for (auto& col_name : map.getFields()) {
          row_json[col_name] = row[col_name].get<std::string>();
        }
        row_json["idx"] = no_pkts++; // Warning: internal state!
        in_pkts.push_back(row_json);
      }
    }

    return map;
  }

  std::string genTsharkCmd(const nlohmann::json config, TSharkMapper& in_map,
                           std::filesystem::path& filepath, size_t cnt) {
    std::string command = config["tshark_path"].get<std::string>();
    command += " " + config["tshark_option"].get<std::string>();
    command += " -Y \"" + config["tshark_displayfilter"].get<std::string>() + "\"";
    command += " -T fields";

    // unordered_map이 빠르지만 여기서는 vector로 저장해둔 걸 써야 정렬된 순서대로 디버깅이 가능
    for (const auto& field : in_map.getFields()) command += " -e \"" + field + "\"";

    command += " -r " + std::string(filepath.c_str());

    std::filesystem::path logfile;
    try {  // https://json.nlohmann.me/features/element_access/checked_access/#notes
      logfile = config.at("fpnt_tshark_error_log").get<std::string>();
    } catch (nlohmann::json::basic_json::out_of_range& e) {
      // Do Nothing
    }
    if (cnt != (size_t) -1)
        logfile.replace_extension( "." + std::to_string(cnt) + logfile.extension().c_str());

    command += " 2>> " + std::string(logfile.c_str());

    // end of command generation

    // if ((fp = popen(command.c_str(), "r")) == NULL) {
    //     cerr << "Info: pcap open is failed! (command: " << command << ")" << endl;
    // }

#ifndef NDEBUG
    std::cout << "File " << filepath << " is now being processed";
    if(config["multiprocessing"])
      std::cout << " by process ID " << getpid();
    std::cout << "..." << std::endl;

    std::cout << command << std::endl;
#endif

    return command;
  }

}  // namespace fpnt
