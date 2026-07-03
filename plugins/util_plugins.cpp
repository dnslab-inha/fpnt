#include "util_plugins.h"

#include <iostream>
#include <sstream>

/**
 * Converts a vector of doubles into a comma-separated string.
 */
std::string vectorToString(const std::vector<double>& vec) {
  std::ostringstream oss;

  // Process the first value to avoid a leading comma
  if (!vec.empty()) {
    oss << vec[0];
  }

  // Process remaining values with a comma separator
  for (size_t i = 1; i < vec.size(); ++i) {
    oss << "," << vec[i];
  }

  return oss.str();
}

/**
 * Converts a comma-separated string into a vector of doubles.
 * This is the inverse operation of vectorToString.
 */
#include <charconv>
#include <string_view>

std::vector<double> stringToVector(std::string_view str) {
  std::vector<double> result;
  if (str.empty()) {
    return result;
  }

  size_t start = 0;
  while (start < str.size()) {
    size_t end = str.find(',', start);
    if (end == std::string_view::npos) {
      end = str.size();
    }

    // std::from_chars requires trimming spaces for best results, but assuming csv values don't have
    // leading spaces to strictly match previous stod behavior, we can optionally skip leading
    // whitespace if needed.
    size_t num_start = start;
    while (num_start < end && std::isspace(static_cast<unsigned char>(str[num_start]))) {
      num_start++;
    }

    if (num_start < end) {
      double val = 0.0;
      auto [ptr, ec] = std::from_chars(str.data() + num_start, str.data() + end, val);
      if (ec == std::errc()) {
        result.push_back(val);
      } else {
        std::cerr << "Conversion error at index " << num_start << "\n";
      }
    }
    start = end + 1;
  }
  return result;
}