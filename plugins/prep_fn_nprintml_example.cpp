#include <nlohmann/json.hpp>
#include <string>
#include <tuple>
#include <utility>

#include "default_keygen.h"
#include "dispatcher_ptr.h"
#include "util_plugins.h"

/** getsubstr retrieves a substring of record[fieldname].get<std::string>() based on the string
 * option and saves it to record[field]. For example, if option is "fieldname,5,10", it extracts the
 * substring from index 5 to 10 from the value of record[fieldname]. If the given string is shorter
 * than the range specified in option, it returns the possible substring. If the given string is
 * empty, record[field] is set to an empty string. For example, when record["supported_group"] =
 * "0x001d,0x0017,0x0018", if option is "supported_group,0,6", the result is "0x001d", and if
 *   option is "supported_group,7,13", the result is "0x0017".
 */
extern "C" void P_getsubstr(std::string& option, nlohmann::json& record,
                            const std::string& granularity, const std::string& key,
                            const std::string& field) {
  size_t first_comma = option.find(',');
  if (first_comma == std::string::npos) {
    std::cerr << "error: invalid option format for P_getsubstr" << std::endl;
    exit(1);
  }

  std::string source_field = option.substr(0, first_comma);

  size_t second_comma = option.find(',', first_comma + 1);
  if (second_comma == std::string::npos) {
    std::cerr << "error: invalid option format for P_getsubstr" << std::endl;
    exit(1);
  }

  int start_idx, end_idx;
  try {
    start_idx = std::stoi(option.substr(first_comma + 1, second_comma - first_comma - 1));
    end_idx = std::stoi(option.substr(second_comma + 1));
  } catch (...) {
    std::cerr << "error: invalid indices in option for P_getsubstr" << std::endl;
    exit(1);
  }

  if (record[source_field].is_null()) {
    record[field] = "";
    return;
  }

  std::string val = record[source_field].get<std::string>();
  if (val.empty()) {
    record[field] = "";
    return;
  }

  if (start_idx < 0) start_idx = 0;
  if (end_idx < start_idx) {
    record[field] = "";
    return;
  }

  size_t start = static_cast<size_t>(start_idx);
  size_t end = static_cast<size_t>(end_idx);

  if (start >= val.length()) {
    record[field] = "";
    return;
  }

  size_t len = end - start + 1;
  if (start + len > val.length()) {
    len = val.length() - start;
  }

  record[field] = val.substr(start, len);
}

/** P_getsubstr_by_comma retrieves a substring of record[fieldname].get<std::string>() based on the
 * string option and saves it to record[field]. For example, if option is "fieldname,0", it extracts
 * the first substring by splitting record[fieldname] with ','. Also, if option is "fieldname,1", it
 * extracts the second substring by splitting record[fieldname] with ','. If
 * record[fieldname].get<std::string>() has no comma, exceeds the range, or is empty,
 * record[field] is set to an empty string. For example, when record["handshake_type"] =
 * "2,11,12,13,14", if option is "handshake_type,0", the result is "2", if option is
 * "handshake_type,1", the result is "11", if option is "handshake_type,5", the result is "".
 */
extern "C" void P_getsubstr_by_comma(std::string& option, nlohmann::json& record,
                                     const std::string& granularity, const std::string& key,
                                     const std::string& field) {
  size_t comma_pos = option.find(',');
  if (comma_pos == std::string::npos) {
    std::cerr << "error: invalid option format for P_getsubstr_by_comma" << std::endl;
    exit(1);
  }

  std::string source_field = option.substr(0, comma_pos);
  int target_idx;
  try {
    target_idx = std::stoi(option.substr(comma_pos + 1));
  } catch (...) {
    std::cerr << "error: invalid index in option for P_getsubstr_by_comma" << std::endl;
    exit(1);
  }

  if (record[source_field].is_null()) {
    record[field] = "";
    return;
  }

  std::string val = record[source_field].get<std::string>();
  if (val.empty() || target_idx < 0) {
    record[field] = "";
    return;
  }

  size_t start = 0;
  size_t end = val.find(',');
  int current_idx = 0;

  while (current_idx < target_idx) {
    if (end == std::string::npos) {
      record[field] = "";
      return;
    }
    start = end + 1;
    end = val.find(',', start);
    current_idx++;
  }

  if (end == std::string::npos) {
    record[field] = val.substr(start);
  } else {
    record[field] = val.substr(start, end - start);
  }
}
