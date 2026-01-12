#include <fpnt/loader.h>

#if defined(__APPLE__)
#  include <pstream.h>

#  include <sstream>
#elif defined(__linux__)
#  include <elf.h>   // ELF64_Sym
#  include <link.h>  // link_map
#else
#  error "Unsupported platform for dynamic symbol listing in loader.cpp"
#endif

#include <string>

namespace fpnt {
  Loader::Loader(std::string path) {
    library_path = path;

    char *error;

    handle = dlopen(library_path.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    // https://stackoverflow.com/questions/25270275/get-functions-names-in-a-shared-library-programmatically

    if (!handle) {
      error = dlerror();
      std::cerr << "____";
      std::cerr << error << std::endl;
      exit(1);
    }

#if defined(__APPLE__)
    // On macOS, use `nm` to list symbols as there is no `dlinfo`.
    // This requires Xcode Command Line Tools to be installed.
    bool find_dispatcher_ptr = false;
    redi::pstream nm_process("nm -gU " + library_path);
    std::string line;

    while (std::getline(nm_process, line)) {
      std::stringstream ss(line);
      std::string address, type, name;
      ss >> address >> type >> name;

      if (name.empty()) continue;

      // `nm` output on macOS often prefixes symbols with an underscore.
      if (name[0] == '_') {
        name = name.substr(1);
      }

      if (type == "T" || type == "t") {  // 'T' is external, 't' is local text symbol
        // It's a function
        if (name.rfind("P_", 0) == 0) {
          map_fns[name] = NULL;
        } else if (name.rfind("genKey_", 0) == 0) {
          map_genkeyfns[name] = NULL;
        }
      } else if (type == "D" || type == "d" || type == "C") {  // 'D'/'d' is data, 'C' is common
        // It's an object
        if (name == "d") {
          find_dispatcher_ptr = true;
        }
      }
    }
#elif defined(__linux__)
    struct link_map *map = nullptr;
    dlinfo(handle, RTLD_DI_LINKMAP, &map);

    Elf64_Sym *symtab = nullptr;
    char *strtab = nullptr;
    int symentries = 0;
    if (map) {
      for (auto section = map->l_ld; section->d_tag != DT_NULL; ++section) {
        if (section->d_tag == DT_SYMTAB) {
          symtab = (Elf64_Sym *)section->d_un.d_ptr;
        }
        if (section->d_tag == DT_STRTAB) {
          strtab = (char *)section->d_un.d_ptr;
        }
        if (section->d_tag == DT_SYMENT) {
          symentries = section->d_un.d_val;
        }
      }
    }

    bool find_dispatcher_ptr = false;
    if (symtab && strtab && symentries > 0) {
      int size = strtab - (char *)symtab;
      for (int k = 0; k < size / symentries; ++k) {
        auto sym = &symtab[k];
        if (ELF64_ST_TYPE(sym->st_info) == STT_FUNC) {
          std::string str = &strtab[sym->st_name];
          if (str.rfind("P_", 0) == 0) {
            map_fns[str] = NULL;
          } else if (str.rfind("genKey_", 0) == 0) {
            map_genkeyfns[str] = NULL;
          }
        } else if (ELF64_ST_TYPE(sym->st_info) == STT_OBJECT) {
          std::string str = &strtab[sym->st_name];
          if (str == "d") {
            find_dispatcher_ptr = true;
          }
        }
      }
    }
#endif
    if (!find_dispatcher_ptr) {
      std::cerr << "Dispatcher's pointer is not available in your library!" << std::endl;
      exit(1);
    }
  }

  bool Loader::validate(const std::string &str_fn) {
    if (str_fn.rfind("P_", 0) == 0) {
      return map_fns.contains(str_fn);
    } else if (str_fn.rfind("genKey_", 0) == 0) {
      return map_genkeyfns.contains(str_fn);
    }
    return false;
  }

  void *Loader::getDispatcherPtr() {
    char *error;
    void *symptr = dlsym(handle, "d");
    if ((error = dlerror()) != NULL) {
      std::cerr << error << std::endl;
      exit(1);
    }
    return symptr;
  }

  fnptr_PrepFn Loader::getPrepFn(std::string &str_fn) {
    fnptr_PrepFn fnptr = NULL;
    if (map_fns.contains(str_fn) && map_fns[str_fn] != NULL) return map_fns[str_fn];

    // if the fnptr is not available
    if (str_fn.substr(0, 2) != "P_") {
      std::cerr << "getPrepFn: the given string does not satisfy the prefix rule 'P_'!"
                << std::endl;
      exit(1);
    }

    char *error;
    void *new_fnptr = dlsym(handle, str_fn.c_str());
    if ((error = dlerror()) != NULL) {
      std::cerr << error << std::endl;
      exit(1);
    }

    fnptr = (fnptr_PrepFn)new_fnptr;
    map_fns[str_fn] = fnptr;

    return fnptr;
  }

  fnptr_genKeyFn Loader::getGenKeyFn(const std::string &str_fn) {
    fnptr_genKeyFn fnptr = NULL;
    if (map_genkeyfns.contains(str_fn) && map_genkeyfns[str_fn] != NULL)
      return map_genkeyfns[str_fn];

    if (str_fn.substr(0, 7) != "genKey_") {
      std::cerr << "getPrepFn: the given string does not satisfy the prefix rule 'genKey_'!"
                << std::endl;
    }

    char *error;
    void *new_fnptr = dlsym(handle, str_fn.c_str());
    if ((error = dlerror()) != NULL) {
      std::cerr << error << std::endl;
      exit(1);
    }

    fnptr = (fnptr_genKeyFn)new_fnptr;
    map_genkeyfns[str_fn] = fnptr;

    return fnptr;
  }

}  // namespace fpnt