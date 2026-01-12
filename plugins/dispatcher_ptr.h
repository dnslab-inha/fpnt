#pragma once

#include <fpnt/dispatcher.h>

namespace fpnt {
  extern "C" fpnt::Dispatcher *d;
  size_t get_idx(std::string key, std::string from, std::string to);
  std::string get_key(std::string key, std::string from, std::string to);
  std::vector<size_t> get_idxs(std::string key, std::string from, std::string to);
  std::vector<std::string> get_keys(std::string key, std::string from, std::string to);
}  // namespace fpnt