#include "util_plugins.h"

#include <iostream>
#include <sstream>

/** */
std::string vectorToString(const std::vector<double>& vec) {
  std::ostringstream oss;

  // process first value
  if (!vec.empty()) {
    oss << vec[0];
  }

  // processing remaining values with comma separator
  for (size_t i = 1; i < vec.size(); ++i) {
    oss << "," << vec[i];
  }

  return oss.str();
}