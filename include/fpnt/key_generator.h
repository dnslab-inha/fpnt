#pragma once

#include <functional>
#include <nlohmann/json.hpp>
#include <string>
#include <unordered_map>
#include <vector>

namespace fpnt {

  struct KeyGenContext {
    const nlohmann::json& pkt;
    std::string& granularity;
    size_t file_idx;
  };

  struct CacheEntry {
    std::vector<std::string> values;
    std::string key_str;
    size_t key_hash;
    nlohmann::json key_data;
  };

  class KeyGenerator {
  protected:
    std::vector<std::string> used_fields;
    std::unordered_map<size_t, std::vector<CacheEntry>> cache;

  public:
    KeyGenerator(std::vector<std::string> fields = {}) : used_fields(fields) {}
    virtual ~KeyGenerator() = default;

    virtual nlohmann::json genKey(const KeyGenContext& ctx) = 0;

    const CacheEntry& getKey(const nlohmann::json& pkt, std::string& granularity, size_t file_idx) {
      size_t h = 0;
      std::vector<std::string> current_values;

      if (!used_fields.empty()) {
        current_values.reserve(used_fields.size());
        for (const auto& field : used_fields) {
          std::string val = "";
          if (pkt.contains(field) && !pkt[field].is_null()) {
            if (pkt[field].is_string()) {
              val = pkt[field].get<std::string>();
            } else {
              val = pkt[field].dump();  // Fallback for numbers, etc.
            }
          }
          current_values.push_back(val);
          // Combine hash
          h ^= std::hash<std::string>{}(val) + 0x9e3779b9 + (h << 6) + (h >> 2);
        }

        // Check cache
        auto it = cache.find(h);
        if (it != cache.end()) {
          for (const auto& entry : it->second) {
            if (entry.values == current_values) {
              return entry;  // Cache hit
            }
          }
        }
      }

      // Cache miss or used_fields is empty (always generate)
      nlohmann::json key_data = genKey({pkt, granularity, file_idx});
      std::string k_str = "";
      std::string key_field = "__" + granularity + "_key";
      if (key_data.contains(key_field) && key_data[key_field].is_string()) {
        k_str = key_data[key_field].get<std::string>();
      }

      size_t k_hash = std::hash<std::string>{}(k_str);

      if (used_fields.empty()) {
        h = k_hash;
        // Even if used_fields is empty, we must cache the returned reference to avoid dangling
        // references
        auto it = cache.find(h);
        if (it != cache.end()) {
          for (const auto& entry : it->second) {
            if (entry.key_str == k_str) return entry;
          }
        }
      }

      CacheEntry new_entry{current_values, k_str, k_hash, key_data};
      cache[h].push_back(new_entry);
      return cache[h].back();
    }
  };

}  // namespace fpnt
