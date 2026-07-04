#ifndef _READER_H
#define _READER_H

#include <fmt/core.h>
#include <fpnt/loader.h>
#include <fpnt/mapper.h>
#include <fpnt/util.h>

#include <cstdio>
#include <cstring>
#include <csv.hpp>
#include <filesystem>
#include <nlohmann/json.hpp>

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
    Reader(){};
    Reader(std::string path) { this->path = path; }
    virtual Mapper& read(Loader* loader = NULL) = 0;
  };

  class CSVReader : public Reader {
  protected:
    csv::CSVFormat format;

  public:
    CSVReader() : Reader(){};
    CSVReader(std::string path, csv::CSVFormat format = default_CSVFormat()) : Reader(path) {
      this->path = path;
      this->format = format;
    };

    Mapper& read(Loader* loader = nullptr);

    virtual ~CSVReader() = default;
  };

  class TSharkCSVReader : public CSVReader {
  private:
    std::string dfref_path;
    std::string version;
    int major;
    int minor;
    int patch;
    bool skip_validation;

    bool compareVersion(std::string);
    FILE* in;

  public:
    TSharkMapper map;
    TSharkCSVReader() = delete;
    TSharkCSVReader(std::string tshark_path, std::string path, std::string dfref_path,
                    bool skip_validation = false, csv::CSVFormat format = default_CSVFormat())
        : CSVReader(path, format), in(popen((tshark_path + " -v").c_str(), "r")) {
      this->dfref_path = dfref_path;
      this->skip_validation = skip_validation;
    }
    ~TSharkCSVReader() {
      if (in) pclose(in);
    }

    TSharkMapper& read(Loader* loader = nullptr);
  };

  class TSharkOutputReader : public Reader {
  private:
    const nlohmann::json config;
    TSharkMapper& map;  // Reader's map is no longer used so hided
    std::string tshark_cmd;
    FILE* in;
    csv::CSVFormat tshark_input_format;
    std::vector<nlohmann::json>& in_pkts;
    [[maybe_unused]] size_t file_idx;

  public:
    TSharkOutputReader(const nlohmann::json config, TSharkMapper& in_map,
                       std::vector<nlohmann::json>& in_pkts, std::filesystem::path in_filepath,
                       size_t counter, [[maybe_unused]] size_t file_idx)
        : Reader(in_filepath.c_str()),
          config(config),
          map(in_map),
          tshark_cmd(genTsharkCmd(config, in_map, in_filepath, counter)),
          in(popen(tshark_cmd.c_str(), "r")),
          tshark_input_format(tshark_csv_fmt(in_map.getFields())),
          in_pkts(in_pkts),
          file_idx(file_idx) {}
    ~TSharkOutputReader() {
      if (in) pclose(in);
    }

    TSharkMapper& read(Loader* loader = nullptr);
  };

}  // namespace fpnt
#endif