#include <fpnt/config.h>

#include <CLI/CLI.hpp>  // help_or_error
#include <nlohmann/json.hpp>
#include <rang.hpp>  // ranbBout, rangBerr, rangout, rangerr

namespace fpnt {
  nlohmann::json parse(int argc, char* argv[]) {
    nlohmann::json config;
    CLI::App app;
    std::atexit([]() { std::cout << rang::style::reset; });

    std::string configPath = "./config.json";
    std::string inputPcapPath = "";  // default: defined in the config file
    std::string outputPath = "";     // default: defined in the config file
    std::string outputType = "";     // default: defined in the config file
    std::string pluginsPath = "";    // default: defined in the config file

    app.add_option("-c,--configpath", configPath, "Path of configuration JSON file");
    app.add_option("-i,--input_pcap", inputPcapPath, "Input pcap path");
    app.add_option("-o,--output", outputPath, "Output path");
    app.add_option("-t,--output-type", outputType,
                   "Output file type (Currently only CSV is supported)");
    app.add_option("-p,--plugins-path", pluginsPath, "Plugins shared object file (.so file) path");

    try {
      app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
      if (e.get_name() != "CallForHelp") {
        std::cout << rang::fg::red;
        std::cout << e.what() << std::endl;
      } else
        std::cout << rang::fg::green;
      exit(app.exit(e));
    }

    std::ifstream i(configPath);
    i >> config;

    if (inputPcapPath != "") config["input_pcap_path"] = inputPcapPath;

    if (outputPath != "") config["output_path"] = outputPath;

    if (pluginsPath != "") config["plugins_path"] = pluginsPath;

    // TODO: CSV output_type override

    if (config["output_stdout_print_granularities"].is_null()) {
      config["output_stdout_print_granularities"] = "";
    }

    if (std::filesystem::absolute(config["input_pcap_path"].get<std::string>())
        == std::filesystem::current_path()) {
      std::cerr << "input_pcap_path must not be the current working directory!" << std::endl;
      exit(1);
    }

    if (std::filesystem::absolute(config["output_path"].get<std::string>())
        == std::filesystem::current_path()) {
      std::cerr << "output_path must not be the current working directory!" << std::endl;
      exit(1);
    }

    if (config["input_pcap_path"].get<std::string>() == ""
        || config["output_path"].get<std::string>() == ""
        || config["output_type"].get<std::string>() == "") {
      std::cerr << "config.json does not have the default parameter! check input_pcap_path, "
                   "output_path, and output_type!"
                << std::endl;
      exit(1);
    }

    // TODO: check output_path should not be included in the input_pcap_path directory

#ifndef NDEBUG
    std::cout << "input_pcap_path: " << config["input_pcap_path"].get<std::string>() << std::endl;
    std::cout << "output_path: " << config["output_path"].get<std::string>() << std::endl;
    std::cout << "plugins_path: " << config["plugins_path"].get<std::string>() << std::endl;
#endif
    return config;
  }

}  // end of namespace fpnt