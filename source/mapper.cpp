#include <fpnt/mapper.h>

namespace fpnt {

  std::string Mapper::getName(size_t idx) const { return idx_to_name[idx]; }
  std::string Mapper::getDesc(size_t idx) const { return idx_to_desc[idx]; }
  std::string Mapper::getType(size_t idx) const { return idx_to_type[idx]; }
  std::vector<std::string> Mapper::getFields() const { return fields; }

  void Mapper::print() {
    for (const auto& field : fields) {
      auto idx = field_to_idx[field];
      auto pref_fns = getPrepFns(field);
      std::cout << "--------------------------------------------" << std::endl;
      std::cout << "Name: " << getName(idx) << std::endl;
      std::cout << "Description: " << getDesc(idx) << std::endl;
      std::cout << "Field: " << field << std::endl;
      std::cout << "Type: " << getType(idx) << std::endl;
      for (auto& [fn, opt] : pref_fns) {
        std::cout << "Function: " << fn << "(" << opt << ")" << std::endl;
      }
      std::cout << "--------------------------------------------" << std::endl;
    }
  }

  std::vector<std::pair<std::string, std::string> > Mapper::getPrepFns(const std::string& field) {
    auto [str_prep_fns, str_options] = prep_fns[field];

    std::vector<std::string> splitted_prep_fns;

    if (str_prep_fns != "") {
      splitted_prep_fns = split_with_trim(str_prep_fns, ";", true);
    }
    std::vector<std::string> splitted_options = split_with_trim(str_options, ";", false);

    size_t x = splitted_prep_fns.size();
    size_t y = splitted_options.size();

    if (x > y) {
      while (splitted_prep_fns.size() > splitted_options.size()) {
        splitted_options.push_back("");
      }
    } else if (x < y) {
      while (splitted_prep_fns.size() < splitted_options.size()) {
        splitted_options.pop_back();
      }
    }

    // now we have x == y
    std::vector<std::pair<std::string, std::string> > result;

    for (size_t i = 0; i < x; i++) {
      result.push_back(make_pair(splitted_prep_fns[i], splitted_options[i]));
    }

    return result;
  }

  void Mapper::setPrepFns(std::string field, std::string str_prep_fns, std::string str_options) {
    trim(str_prep_fns);
    trim(str_options);

    prep_fns[field] = make_pair(str_prep_fns, str_options);
  }

  size_t Mapper::addField(std::string field, std::string name, std::string desc, std::string type) {
    size_t idx = idx_to_name.size();

    if (field_to_idx.find(field) == field_to_idx.end()) {
      field_to_idx[field] = idx;
      idx_to_name.push_back(name);
      idx_to_desc.push_back(desc);
      idx_to_type.push_back(type);
    } else {
      std::cerr << "Mapper: Duplicate field key!" << std::endl;
      exit(1);
    }

    fields.push_back(field);

    return idx;
  }

  size_t Mapper::operator[](std::string& field) {
    if (field_to_idx.find(field) != field_to_idx.end())
      return field_to_idx[field];
    else
      return -1;
  }

  size_t TSharkMapper::addField(std::string field, std::string name, std::string desc,
                                std::string type, std::string ver) {
    size_t idx = Mapper::addField(field, name, desc, type);
    idx_to_ver.push_back(ver);

    return idx;
  }

  void TSharkMapper::print() {
    for (const auto& field : fields) {
      auto idx = field_to_idx[field];
      std::cout << "--------------------------------------------" << std::endl;
      std::cout << "Name: " << getName(idx) << std::endl;
      std::cout << "Description: " << getDesc(idx) << std::endl;
      std::cout << "Field: " << field << std::endl;
      std::cout << "Type: " << getType(idx) << std::endl;
      std::cout << "Versions: " << getVer(idx) << std::endl;
      std::cout << "--------------------------------------------" << std::endl;
    }
  }

}  // end of namespace fpnt