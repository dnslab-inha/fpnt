#ifndef _CONFIG_H
#define _CONFIG_H

#include <nlohmann/json.hpp>

namespace fpnt
{
    nlohmann::json parse(int argc, char* argv[]);
}

#endif