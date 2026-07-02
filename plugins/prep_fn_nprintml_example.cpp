#include <nlohmann/json.hpp>
#include <string>
#include <tuple>
#include <utility>

#include "default_keygen.h"
#include <fpnt/plugin_context.h>
#include "util_plugins.h"

/** getsubstr retrieves a substring of ctx.getRecord()[fieldname].get<std::string>() based on the string
 * ctx.getOption() and saves it to ctx.getRecord()[ctx.getField()]. For example, if ctx.getOption() is "fieldname,5,10", it extracts the
 * substring from index 5 to 10 from the value of ctx.getRecord()[fieldname]. If the given string is shorter
 * than the range specified in ctx.getOption(), it returns the possible substring. If the given string is
 * empty, ctx.getRecord()[ctx.getField()] is set to an empty string. For example, when ctx.getRecord()["supported_group"] =
 * "0x001d,0x0017,0x0018", if ctx.getOption() is "supported_group,0,6", the result is "0x001d", and if
 *   ctx.getOption() is "supported_group,7,13", the result is "0x0017".
 */
extern "C" void P_getsubstr(fpnt::PluginContext& ctx) {
  size_t first_comma = ctx.getOption().find(',');
  if (first_comma == std::string::npos) {
    std::cerr << "error: invalid ctx.getOption() format for P_getsubstr" << std::endl;
    exit(1);
  }

  std::string source_field = ctx.getOption().substr(0, first_comma);

  size_t second_comma = ctx.getOption().find(',', first_comma + 1);
  if (second_comma == std::string::npos) {
    std::cerr << "error: invalid ctx.getOption() format for P_getsubstr" << std::endl;
    exit(1);
  }

  int start_idx, end_idx;
  try {
    start_idx = std::stoi(ctx.getOption().substr(first_comma + 1, second_comma - first_comma - 1));
    end_idx = std::stoi(ctx.getOption().substr(second_comma + 1));
  } catch (...) {
    std::cerr << "error: invalid indices in ctx.getOption() for P_getsubstr" << std::endl;
    exit(1);
  }

  if (ctx.getRecord()[source_field].is_null()) {
    ctx.getRecord()[ctx.getField()] = "";
    return;
  }

  const auto& val = ctx.getRecord()[source_field].get_ref<const std::string&>();
  if (val.empty()) {
    ctx.getRecord()[ctx.getField()] = "";
    return;
  }

  if (start_idx < 0) start_idx = 0;
  if (end_idx < start_idx) {
    ctx.getRecord()[ctx.getField()] = "";
    return;
  }

  size_t start = static_cast<size_t>(start_idx);
  size_t end = static_cast<size_t>(end_idx);

  if (start >= val.length()) {
    ctx.getRecord()[ctx.getField()] = "";
    return;
  }

  size_t len = end - start + 1;
  if (start + len > val.length()) {
    len = val.length() - start;
  }

  ctx.getRecord()[ctx.getField()] = val.substr(start, len);
}

/** P_getsubstr_by_comma retrieves a substring of ctx.getRecord()[fieldname].get<std::string>() based on the
 * string ctx.getOption() and saves it to ctx.getRecord()[ctx.getField()]. For example, if ctx.getOption() is "fieldname,0", it extracts
 * the first substring by splitting ctx.getRecord()[fieldname] with ','. Also, if ctx.getOption() is "fieldname,1", it
 * extracts the second substring by splitting ctx.getRecord()[fieldname] with ','. If
 * ctx.getRecord()[fieldname].get<std::string>() has no comma, exceeds the range, or is empty,
 * ctx.getRecord()[ctx.getField()] is set to an empty string. For example, when ctx.getRecord()["handshake_type"] =
 * "2,11,12,13,14", if ctx.getOption() is "handshake_type,0", the result is "2", if ctx.getOption() is
 * "handshake_type,1", the result is "11", if ctx.getOption() is "handshake_type,5", the result is "".
 */
extern "C" void P_getsubstr_by_comma(fpnt::PluginContext& ctx) {
  size_t comma_pos = ctx.getOption().find(',');
  if (comma_pos == std::string::npos) {
    std::cerr << "error: invalid ctx.getOption() format for P_getsubstr_by_comma" << std::endl;
    exit(1);
  }

  std::string source_field = ctx.getOption().substr(0, comma_pos);
  int target_idx;
  try {
    target_idx = std::stoi(ctx.getOption().substr(comma_pos + 1));
  } catch (...) {
    std::cerr << "error: invalid index in ctx.getOption() for P_getsubstr_by_comma" << std::endl;
    exit(1);
  }

  if (ctx.getRecord()[source_field].is_null()) {
    ctx.getRecord()[ctx.getField()] = "";
    return;
  }

  const auto& val = ctx.getRecord()[source_field].get_ref<const std::string&>();
  if (val.empty() || target_idx < 0) {
    ctx.getRecord()[ctx.getField()] = "";
    return;
  }

  size_t start = 0;
  size_t end = val.find(',');
  int current_idx = 0;

  while (current_idx < target_idx) {
    if (end == std::string::npos) {
      ctx.getRecord()[ctx.getField()] = "";
      return;
    }
    start = end + 1;
    end = val.find(',', start);
    current_idx++;
  }

  if (end == std::string::npos) {
    ctx.getRecord()[ctx.getField()] = val.substr(start);
  } else {
    ctx.getRecord()[ctx.getField()] = val.substr(start, end - start);
  }
}
