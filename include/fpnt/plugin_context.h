#pragma once

#include <fpnt/mapper.h>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include <unordered_map>

namespace fpnt {

  // Forward declaration of Dispatcher
  class Dispatcher;

  class PluginContext {
  private:
    Dispatcher* d;
    std::string option;
    nlohmann::json* record;
    std::string granularity;
    std::string key;
    std::string field;

  public:
    PluginContext(Dispatcher* d, const std::string& option, nlohmann::json& record,
                  const std::string& granularity, const std::string& key,
                  const std::string& field);

    // Getters
    const std::string& getOption() const;
    nlohmann::json& getRecord() const;
    const std::string& getGranularity() const;
    const std::string& getKey() const;
    const std::string& getField() const;

    // Helper functions for Dispatcher data access
    std::vector<std::string> getChildKeys() const;
    nlohmann::json& getChildRecord(const std::string& child_key) const;

    // Additional helper functions migrated from dispatcher_ptr
    size_t getIdx(std::string key, std::string from, std::string to) const;
    std::string getKey(std::string key, std::string from, std::string to) const;
    std::vector<size_t> getIdxs(std::string key, std::string from, std::string to) const;
    std::vector<std::string> getKeys(std::string key, std::string from, std::string to) const;

    std::vector<nlohmann::json>& getInPkts() const;
    fpnt::TSharkMapper& getInMap() const;
    std::unordered_map<std::string, std::unordered_map<std::string, size_t>>& getOutKey2Idx() const;
    nlohmann::json& getRecordByGranularity(const std::string& g, const std::string& k) const;
  };

}  // namespace fpnt
