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
std::vector<double> stringToVector(const std::string& str) {
  std::vector<double> result;

  // Handle the case where the input string is empty
  if (str.empty()) {
    return result;
  }

  std::stringstream ss(str);
  std::string item;

  // Split the string using the comma (',') as a delimiter
  while (std::getline(ss, item, ',')) {
    try {
      // Convert string token to double and add to vector
      // std::stod handles leading/trailing whitespace automatically
      result.push_back(std::stod(item));
    } catch (const std::exception& e) {
      // Handle cases where conversion fails (e.g., non-numeric data)
      std::cerr << "Conversion error: " << e.what() << std::endl;
    }
  }

  return result;
}