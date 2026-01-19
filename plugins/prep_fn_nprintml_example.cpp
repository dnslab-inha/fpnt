#include <nlohmann/json.hpp>
#include <string>
#include <tuple>
#include <utility>

#include "default_keygen.h"
#include "dispatcher_ptr.h"
#include "util_plugins.h"

/** getsubstr은 문자열 option에 따라 record[fieldname].get<std::string>()의 부분 문자열을 가져와 record[field]에 저장하는 함수이다.
 * 예를 들어, option이 "fieldname,5,10"이라면, record[fieldname]의 값에서 인덱스 5부터 10까지의 부분 문자열을 추출한다.
 * 만약 주어진 문자열이 option에서 지정한 범위보다 짧다면, 가능한 부분 문자열을 반환한다.
 * 만약 주어진 문자열이 비어있다면, record[field]는 빈 문자열로 설정된다.
 * 예를 들어, record["supported_group"] = "0x001d,0x0017,0x0018"일 때,
 *   option이 "supported_group,0,6"이라면, 결과는 "0x001d"가 되며,
 *   option이 "supported_group,7,13"이라면, 결과는 "0x0017"이 된다.
 */
extern "C" void P_getsubstr(std::string& option, nlohmann::json& record, const std::string& granularity,
                        const std::string& key, const std::string& field) {
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

/** P_getsubstr_by_comma은 문자열 option에 따라 record[fieldname].get<std::string>()의 부분 문자열을 가져와 record[field]에 저장하는 함수이다.
 * 예를 들어, option이 "fieldname,0"이라면, record[fieldname]를 ','로 구분하여 첫 번째 부분 문자열을 추출한다.
 * 또한, option이 "fieldname,1"이라면, record[fieldname]를 ','로 구분하여 두 번째 부분 문자열을 추출한다.
 * 만약 record[fieldname].get<std::string>()에 컴마가 없거나, 범위를 넘어서거나, 문자열이 비어있다면, record[field]는 빈 문자열로 설정된다.
 * 예를 들어, record["handshake_type"] = "2,11,12,13,14"일 때,
 *   option이 "handshake_type,0"이라면, 결과는 "2"가 되며,
 *   option이 "handshake_type,1"이라면, 결과는 "11"이 된다.
 *   option이 "handshake_type,5"이라면, 결과는 ""가 된다.
 */
extern "C" void P_getsubstr_by_comma(std::string& option, nlohmann::json& record, const std::string& granularity,
                        const std::string& key, const std::string& field) {
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
