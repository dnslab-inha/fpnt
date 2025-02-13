#ifndef _READER_H
#define _READER_H

#include <fmt/core.h>
#include <fpnt/loader.h>
#include <fpnt/mapper.h>
#include <fpnt/util.h>
#include <pstream.h>

#include <cstring>
#include <csv.hpp>
#include <filesystem>
#include <fstream>
#include <locale>
#include <nlohmann/json.hpp>
#include <unordered_map>

namespace fpnt {

  std::string genTsharkCmd(const nlohmann::json config, TSharkMapper& in_map,
                           std::filesystem::path& filepath, size_t cnt = -1);

  csv::CSVFormat tshark_csv_fmt(std::vector<std::string> fields);
  csv::CSVFormat default_CSVFormat();

  class Reader {
  protected:
    std::string path;

  public:
    Mapper map;
    Reader() {};
    Reader(std::string path) { this->path = path; }
    virtual Mapper& read(Loader* loader = NULL) = 0;
  };

  class CSVReader : public Reader {
  protected:
    csv::CSVFormat format;

  public:
    CSVReader() : Reader() {};
    CSVReader(std::string path, csv::CSVFormat format = default_CSVFormat())
        : Reader(path) {
      this->path = path;
      this->format = format;
    };

    Mapper& read(Loader* loader = nullptr);
  };

  class TSharkCSVReader : public CSVReader {
  private:
    std::string dfref_path;
    std::string version;
    int major;
    int minor;
    int patch;

    bool compareVersion(std::string );
    redi::ipstream in;

  public:
    TSharkMapper map;
    TSharkCSVReader() = delete;
    TSharkCSVReader(std::string tshark_path, std::string path, std::string dfref_path,
                    csv::CSVFormat format = default_CSVFormat())
        : CSVReader(path, format),
          in(redi::ipstream(tshark_path + " -v"))
        {
      this->dfref_path = dfref_path;
    }

    TSharkMapper& read(Loader* loader = nullptr);
  };

  class TSharkOutputReader : public Reader {
  private:
    const nlohmann::json config;
    TSharkMapper& map;  // Reader's map is no longer used so hided
    std::string tshark_cmd;
    redi::ipstream in;
    csv::CSVFormat tshark_input_format;
    std::vector<nlohmann::json>& in_pkts;

  public:
    TSharkOutputReader(const nlohmann::json config, TSharkMapper& in_map,
                       std::vector<nlohmann::json>& in_pkts, std::filesystem::path in_filepath, size_t counter)
        : Reader(in_filepath.c_str()),
          config(config),
          map(in_map),
          tshark_cmd(genTsharkCmd(config, in_map, in_filepath, counter)),
          in(redi::ipstream(tshark_cmd)),
          tshark_input_format(tshark_csv_fmt(in_map.getFields())),
          in_pkts(in_pkts)
          {}

    TSharkMapper& read(Loader* loader = nullptr);
    
  };



}  // namespace fpnt
#endif