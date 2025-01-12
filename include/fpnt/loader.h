#ifndef _LOADER_H
#define _LOADER_H

#include <fpnt/mapper.h>
#include <dlfcn.h>
#include <string>
#include <iostream>
#include <elf.h> // ELF64_Sym
#include <link.h>  // link_map
#include <vector>
#include <nlohmann/json.hpp>

namespace fpnt
{

    typedef void (*fnptr_PrepFn)(const std::string&, nlohmann::json&, std::string&, const std::string&, const std::string&);
    typedef const std::string (*fnptr_genKeyFn)(const nlohmann::json&, std::string&, std::string&);

class Loader {
    private:
        std::string library_path;
        void *handle;
        std::vector<std::string> fns;

    public:
        Loader(std::string path);

        ~Loader() {
            dlclose(handle);
        }

        bool validate(const std::string& prep_fn);

        void* getDispatcherPtr();

        fnptr_PrepFn getPrepFn(std::string& str_fn);

        fnptr_genKeyFn getGenKeyFn(const std::string& str_fn);

        void printFns() { for( auto &x: fns) std::cout << x << std::endl; }
};


}

#endif