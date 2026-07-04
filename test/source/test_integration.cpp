#include <doctest/doctest.h>

#include <cstdlib>
#include <iostream>
#include <string>

int run_fpnt(const std::string& config, const std::string& input_dir,
             const std::string& output_dir) {
  std::string executable = std::string(FPNT_BINARY_DIR) + "/_deps/fpnt-build/standalone/fpnt";
  std::string plugin_path
      = std::string(FPNT_BINARY_DIR) + "/_deps/fpnt-build/plugins/libFPNT_PLUGINS.so";

  // Use cd to project source directory so relative paths in config files work properly
  std::string cmd = "cd " + std::string(FPNT_SOURCE_DIR) + " && " + executable + " -c " + config
                    + " -i " + input_dir + " -o " + output_dir + " -p " + plugin_path;

  std::cout << "Running: " << cmd << std::endl;
  return std::system(cmd.c_str());
}

TEST_CASE("Integration tests for various configs") {
  std::string bfm_pcap = std::string(FPNT_SOURCE_DIR) + "/test/datasets/bfm";
  std::string mta_pcap = std::string(FPNT_SOURCE_DIR) + "/test/datasets/mta";
  std::string out_dir = std::string(FPNT_BINARY_DIR) + "/output_test";

  SUBCASE("Typical test") {
    int res = run_fpnt("config.json", mta_pcap, out_dir);
    CHECK(res == 0);
  }

  SUBCASE("BFM test") {
    int res = run_fpnt("config_bfm.json", bfm_pcap, out_dir);
    CHECK(res == 0);
  }

  SUBCASE("MTA Comparison test") {
    int res = run_fpnt("config_mta-compare.json", mta_pcap, out_dir);
    CHECK(res == 0);
  }

  SUBCASE("MTA 5Tuple test") {
    int res = run_fpnt("config_mta-5tuple.json", mta_pcap, out_dir);
    CHECK(res == 0);
  }
}
