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

  std::string genTsharkCmd(const nlohmann::json config, TSharkMapper& map_t,
                           std::filesystem::path& filepath, size_t cnt = -1);

  csv::CSVFormat tshark_csv_fmt(std::vector<std::string> fields);
  csv::CSVFormat default_CSVFormat();

  class Reader {
  protected:
    std::string path;
    Mapper map;

  public:
    Reader() = delete;
    Reader(std::string path) { this->path = path; }
    virtual Mapper& read(Loader* loader = NULL) = 0;
  };

  class CSVReader : public Reader {
  protected:
    csv::CSVFormat format;
    csv::CSVReader internal_reader;

  public:
    CSVReader() = delete;
    CSVReader(std::string path, csv::CSVFormat format = default_CSVFormat())
        : Reader(path), internal_reader(path, format) {
      this->path = path;
      this->format = format;
    };

    Mapper& read(Loader* loader = nullptr);
  };

  class TSharkCSVReader : public CSVReader {
  private:
    std::string dfref_path;
    TSharkMapper map;

  public:
    TSharkCSVReader() = delete;
    TSharkCSVReader(std::string path, std::string dfref_path,
                    csv::CSVFormat format = default_CSVFormat())
        : CSVReader(path, format) {
      this->dfref_path = dfref_path;
    }

    TSharkMapper& read(Loader* loader = nullptr);
  };

  class TSharkOutputReader : public Reader {
  private:
    const nlohmann::json config;
    TSharkMapper& map;
    std::string tshark_cmd;
    redi::ipstream in;
    csv::CSVFormat tshark_input_format;
    std::vector<nlohmann::json>& in_pkts;
    size_t counter;

  public:
    TSharkOutputReader(const nlohmann::json config, TSharkMapper& map_t,
                       std::vector<nlohmann::json>& in_pkts, std::filesystem::path in_filepath, size_t counter)
        : Reader(in_filepath.c_str()),
          config(config),
          map(map_t),
          tshark_cmd(genTsharkCmd(config, map_t, in_filepath, counter)),
          in(redi::ipstream(tshark_cmd)),
          tshark_input_format(tshark_csv_fmt(map_t.getFields())),
          in_pkts(in_pkts),
          counter(counter) {}

    TSharkMapper& read(Loader* loader = nullptr);
    
  };



}  // namespace fpnt
#endif