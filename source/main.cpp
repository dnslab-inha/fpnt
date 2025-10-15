#include <fpnt/config.h>
#include <fpnt/dispatcher.h>

#include <filesystem>
#include <iostream>
#include <rang.hpp>  // ranbBout, rangBerr, rangout, rangerr
#include <set>
#include <string>
#include <unordered_map>

using namespace fpnt;

auto main(int argc, char** argv) -> int {
  auto config = parse(argc, argv);

#ifndef NDEBUG
  std::cout << "Config JSON dump: " << config.dump() << std::endl;
#endif

  Dispatcher d(config);

  d.dispatch();

  // only the one process (i.e., parent) can arrive at this point

  // TODO: file aggregator?

  return 0;
}
