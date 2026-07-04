#include <doctest/doctest.h>

#include <cstdlib>
#include <iostream>
#include <string>

#ifndef FPNT_EXECUTABLE_PATH
#  define FPNT_EXECUTABLE_PATH ""
#endif

#ifndef FPNT_PLUGIN_PATH
#  define FPNT_PLUGIN_PATH ""
#endif

#ifndef FPNT_SOURCE_DIR
#  define FPNT_SOURCE_DIR ""
#endif

#ifndef FPNT_BINARY_DIR
#  define FPNT_BINARY_DIR ""
#endif

static bool dir_exists(const std::string& path) {
  // Use stat to check if directory exists
  std::string cmd = "test -d \"" + path + "\"";
  return std::system(cmd.c_str()) == 0;
}

int run_fpnt(const std::string& config, const std::string& input_dir,
             const std::string& output_dir) {
  std::string executable = FPNT_EXECUTABLE_PATH;
  std::string plugin_path = FPNT_PLUGIN_PATH;

  // Use cd to project source directory so relative paths in config files work properly
  std::string cmd = "cd " + std::string(FPNT_SOURCE_DIR) + " && " + executable + " -c " + config
                    + " -i " + input_dir + " -o " + output_dir + " -p " + plugin_path
                    + " --skip-dfref-validation";

  std::cout << "Running: " << cmd << std::endl;
  return std::system(cmd.c_str());
}

TEST_CASE("Integration tests for various configs") {
  std::string mta_pcap = std::string(FPNT_SOURCE_DIR) + "/test/datasets/mta";
  std::string bfm_pcap = std::string(FPNT_SOURCE_DIR) + "/test/datasets/bfm";
  std::string out_dir = std::string(FPNT_BINARY_DIR) + "/output_test";

  SUBCASE("Typical test") {
    if (!dir_exists(mta_pcap)) {
      MESSAGE("Skipping: test/datasets/mta not found");
      return;
    }
    int res = run_fpnt("config.json", mta_pcap, out_dir);
    CHECK(res == 0);
  }

  SUBCASE("BFM test") {
    if (!dir_exists(bfm_pcap)) {
      MESSAGE("Skipping: test/datasets/bfm not found");
      return;
    }
    int res = run_fpnt("config_bfm.json", bfm_pcap, out_dir);
    CHECK(res == 0);
  }

  SUBCASE("MTA Comparison test") {
    if (!dir_exists(mta_pcap)) {
      MESSAGE("Skipping: test/datasets/mta not found");
      return;
    }
    int res = run_fpnt("config_mta-comparison.json", mta_pcap, out_dir);
    CHECK(res == 0);
  }

  SUBCASE("MTA 5Tuple test") {
    if (!dir_exists(mta_pcap)) {
      MESSAGE("Skipping: test/datasets/mta not found");
      return;
    }
    int res = run_fpnt("config_mta-5tuple.json", mta_pcap, out_dir);
    CHECK(res == 0);
  }
}
