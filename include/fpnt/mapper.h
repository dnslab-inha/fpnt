#ifndef _MAPPER_H
#define _MAPPER_H

#include <fpnt/util.h>

#include <iostream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace fpnt {

  class Mapper {
  protected:
    std::unordered_map<std::string, size_t> field_to_idx;  // field key to idx
    std::vector<std::string> idx_to_name;
    std::vector<std::string> idx_to_desc;
    std::vector<std::string> idx_to_type;
    std::unordered_map<std::string, std::pair<std::string, std::string> > prep_fns;
    std::vector<std::string> fields;

  public:
    size_t operator[](std::string& field);
    std::string getName(size_t idx) const;
    std::string getDesc(size_t idx) const;
    std::string getType(size_t idx) const;
    std::vector<std::string> getFields() const;

    void print();
    std::vector<std::pair<std::string, std::string> > getPrepFns(const std::string& field);
    void setPrepFns(std::string field, std::string str_prep_fns, std::string str_options);
    size_t addField(std::string field, std::string name, std::string desc = "",
                    std::string type = "");
  };

  class TSharkMapper : public Mapper {
  private:
    std::vector<std::string> idx_to_ver;

  public:
    std::string getVer(size_t idx) const { return idx_to_ver[idx]; }

    size_t addField(std::string field, std::string name, std::string desc = "",
                    std::string type = "", std::string ver = "");

    void print();
  };

}  // namespace fpnt

#endif