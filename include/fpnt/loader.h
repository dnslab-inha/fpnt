#ifndef _LOADER_H
#define _LOADER_H

#include <dlfcn.h>
#include <fpnt/key_generator.h>
#include <fpnt/mapper.h>
#include <fpnt/plugin_context.h>

#include <iostream>
#include <nlohmann/json.hpp>
#include <string>

namespace fpnt {
  typedef void (*fnptr_PrepFn)(fpnt::PluginContext&);
  typedef KeyGenerator* (*fnptr_createKeyGenFn)();

  class Loader {
  private:
    std::string library_path;
    void* handle;
    std::map<std::string, fnptr_PrepFn> map_fns;
    std::map<std::string, KeyGenerator*> map_genkeyfns;

  public:
    Loader(std::string path);

    ~Loader() {
      for (auto& pair : map_genkeyfns) {
        delete pair.second;
      }
      dlclose(handle);
    }

    fnptr_PrepFn getPrepFn(std::string& str_fn);

    bool validate(const std::string& str_fn);

    KeyGenerator* getGenKeyFn(const std::string& str_fn);

    void printFns() {
      for (const auto& x : map_fns) std::cout << x.first << std::endl;
    }

    void printGenKeyFns() {
      for (const auto& x : map_genkeyfns) std::cout << x.first << std::endl;
    }
  };

}  // namespace fpnt

#endif