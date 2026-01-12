#ifndef _LOADER_H
#define _LOADER_H

#include <dlfcn.h>
#include <fpnt/mapper.h>

#include <iostream>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace fpnt {
  typedef void (*fnptr_PrepFn)(const std::string&, nlohmann::json&, std::string&,
                               const std::string&, const std::string&);
  typedef const std::string (*fnptr_genKeyFn)(const nlohmann::json&, std::string&, std::string&);

  class Loader {
  private:
    std::string library_path;
    void* handle;
    std::map<std::string, fnptr_PrepFn> map_fns;
    std::map<std::string, fnptr_genKeyFn> map_genkeyfns;

  public:
    Loader(std::string path);

    ~Loader() { dlclose(handle); }

    void* getDispatcherPtr();

    fnptr_PrepFn getPrepFn(std::string& str_fn);

    bool validate(const std::string& str_fn);

    fnptr_genKeyFn getGenKeyFn(const std::string& str_fn);

    void printFns() {
      for (const auto& x : map_fns) std::cout << x.first << std::endl;
    }

    void printGenKeyFns() {
      for (const auto& x : map_genkeyfns) std::cout << x.first << std::endl;
    }
  };

}  // namespace fpnt

#endif