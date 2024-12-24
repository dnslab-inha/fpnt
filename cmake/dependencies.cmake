
# How to add Libraries using CPM's CPMAddPackage
# Examples
# CPMAddPackage("gh:vincentlaucsb/csv-parser#2.2.1") # csv-parser does not use version (prefix 'v' is added in tag) in their repository
# CPMAddPackage("gh:CLIUtils/CLI11@2.3.2") # CLI11 uses the version prefix in their repository
# gh: github,  @ version, # tag

CPMAddPackage("gh:fmtlib/fmt#master")
CPMAddPackage("gh:nlohmann/json#master") # CMakeLists.txt available; nlohmann_json
CPMAddPackage("gh:jwakely/pstreams#master")
CPMAddPackage("gh:CLIUtils/CLI11#main")
CPMAddPackage("gh:agauniyal/rang#master")
CPMAddPackage("gh:vincentlaucsb/csv-parser#master")



