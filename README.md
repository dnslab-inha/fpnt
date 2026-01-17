# fpnt: an open source flexible preprocessing framework for network traffic analysis

`fpnt` is a C++-based framework to preprocess packet capture files (in `pcap` or `pcapng` format) in order to generate the corresponding Comma-Separated Values (CSV) files with varying levels of traffic granularity: packet, flow, and flowset. For each packet in the packet capture files, extracting and preprocessing various features is possible with the help of `tshark`-based decoding and filtering. Furthermore, by changing (or choosing) the flow and flowset key generation functions written in C++, you can define the notion of flow and flowset for your specific purpose. In addition, loading preprocessing functions as plugins (*i.e.*, shared object in Unix-like systems) is also supported in `fpnt`. Currently, `fpnt` only supports Unix-like systems, and has been tested in Ubuntu Linux.

## How to build

To build `fpnt`, you need to install `cmake` and compiler (e.g., `gcc`). The following command installs them in Ubuntu:

```
sudo apt install cmake build-essential -y
```

You can build the `fpnt` source code in either Debug mode or Release mode.

### Debug mode

Debug mode can provide a detailed output during execution.

```
mkdir build
cmake -DCMAKE_BUILD_TYPE=Debug -S./all -Bbuild
cmake --build ./build --config Debug
```

### Release mode

`fpnt` built in Release mode prints minimal output during execution.

```
mkdir build
cmake -DCMAKE_BUILD_TYPE=Release -S./all -Bbuild
cmake --build ./build --config Release
```

### Locations of important files

If you follow the above instructions in either mode, the standlone `fpnt` program will be stored as `build/standalone/fpnt` (or `build/_deps/fpnt-build/standalone/fpnt` when using ninja or similar low-level build systems). You need to aware a plugin file (*i.e.*, a shared object file in Unix-like systems) stored as `build/plugins/libFPNT_PLUGINS.so` (or `build/_deps/fpnt-build/plugins/libFPNT_PLUGINS.so` when using ninja or similar low-level build systems), since this file is required for executing `fpnt`, while its location can be changed. For more information, check [Requirements](#requirements) section.

### How to install and run (Recommended)

If you want to install `fpnt` in your home directory, you can use the following command. This command will install `fpnt` into `$HOME/fpnt_release`.

```
sudo cmake --build build --target install
cd $HOME/fpnt_release
```

If you want to change the root directory of `fpnt` to `path-to-fpnt-root`, you can use the following command for installing `fpnt`.

```
sudo cmake --build build --target install -DCMAKE_INSTALL_PREFIX=path-to-fpnt-root
cd path-to-fpnt-root
```

After copying your pcap files into `input_mta` subdirectory, you can run `fpnt with the default mta configruation.
```
mkdir input_mta
cp $HOME/2013-06-18-Neutrino-EK-traffic.pcap ./input_mta/
fpnt (or ./fpnt if you does not use sudo when installing)
```

## How to execute (without install)

To execute `fpnt`, several requirements should be satisfied, while some of them can be configured through `config.json`.

### Requirements

`fpnt` requires to install `tshark` for execution. You can install `tshark` in Ubuntu using the following command. If the `tshark` path is different, you need to change `tshark_path` field in `config.json`.

```
sudo apt install tshark -y
```

`fpnt` requires to have a JSON file called `config.json` in the current working directory (CWD). A template `config.json` is provided in the root source directory of `fpnt`.

`fpnt` requires to have a directory called `dfref` to validate `tshark`-decoded input feature configuration. This directory contains HTML files referred by `https://www.wireshark.org/docs/dfref/`. You can crawl the HTML files by executing the given python crawler `crawl_dfref.py`. Note that this python file requires [Python 3](https://www.python.org/downloads/), [Requests](https://requests.readthedocs.io/en/latest/), and [BeautifulSoup 4](https://pypi.org/project/beautifulsoup4/). While the following command is NOT recommended, you can install Python 3, Requests, and BeautifulSoup 4 in Ubuntu using the following command:
```
sudo apt install python3 python3-requests python3-bs4 -y
```

Note that if you installed Python 3 and `pip`, you can install Requests, and BeautifulSoup 4 using the following command:
```
pip install bs4 requests
```

You can now crawl the HTML files:
```
python3 ./crawl_dfref.py
```

Your packet capture files should be located in the `input_pcap_path` directory (e.g., `input_mta`, `input_bfm`) and the resulting CSV files will be located in the `output_path` directory (e.g., `output`). If a packet capture file is located in a subdirectory of the `input_pcap_path` directory, the output CSV file will be located, following its relative path to the `output_path` directory. You can change the `input_pcap_path` and `output_path` locations from the corresponding fields in `config.json`. Note that when `fpnt` is executed, the `output_path` directory will be removed if it exists and the `force_remove` field in `config.json` is set to `true`. If the `force_remove` field is set to `false`, the `output_path` directory will not be removed but if it exists, `fpnt` will be terminated without processing.

`fpnt` requires several CSV files for extracting `tshark`-decoded input features and storing preprocessed output features in different level of traffic granularity. These CSV files should be located in the directory specified in the `configcsv_path` field of `config.json`.

* `config_*/input_tshark.csv`: specifies `tshark`-decoded input features for each packet. A simple validation (just checking the existence of the features from the crawled `tshark` display filter references)
* `config_*/output_pkt.csv`: specifies output features for each packet. In each row of this CSV file, you need to specify preprocessing functions (`P_*` functions) with options in order. Semicolon (`;`) is used for splitting multiple functions (and options) in order.
* `config_*/output_flow.csv`: specifies output features for each flow. In each row of this CSV file, you need to specify preprocessing functions (`P_*` functions) with options in order. Semicolon (`;`) is used for splitting multiple functions (and options) in order.
* `config_*/output_flowset.csv`: specifies output features for each flowset. In each row of this CSV file, you need to specify preprocessing functions (`P_*` functions) with options in order. Semicolon (`;`) is used for splitting multiple functions (and options) in order.

To execute `fpnt` executable file, the plugin file `libFPNT_PLUGINS.so` is required. As described in [Locations of important files](#locations-of-important-files) section, building `fpnt` with build directory `build` generates `build/plugins/libFPNT_PLUGINS.so`. This plugin file contains `genKey_*` functions for key generation and `P_*` functions for preprocessing of each output field. These functions are not available in the `fpnt` executable file and will be dynamically loaded when `fpnt` is executed. When the location is changed, you need to change the `plugins_path` field in `config.json`.

### Executing the `fpnt` executable file

If you do not move the executable file, you can execute `fpnt` using the following command in the root directory of the repository:
```
build/_deps/fpnt-build/standalone/fpnt
```

If you want to execute fpnt in a specific direcory, make sure `config.json` is available in the same directory and you must modify several directory/file paths in `config.json` appropriately.

## More on configurations

* `fpnt` supports multiprocessing by dispatching each file to different process up to the number of CPUs automatically. However, you can turn off the feature by changing the `multiprocessing` field in `config.json` to `false`. It could be useful for debugging `fpnt` source code.
* Currently, the `output_type` field in `config.json` must be set to `csv`, since other output types are not supported.
* You can customize the `genKey_*` fields in `config.json`, if you define a new `genKey_*` functions in the plugin file. The default `genKey_*` functions are defined in `plugins/default_keygen.cpp` and their interfaces are declared in `plugins/default_keygen.h`.
* The `early_stop_pkts` (per pcap file) field in `config.json` can be used to limit the number of packets to be processed for each file. If the field is set to `-1`, then the early stopping will not work. If the field is set to `0`, no files will not be processed and `fpnt` will be terminated. If the field has positive values, the early stopping will work.
* The `tshark_displayfiler` field in `config.json` can be used for controlling `tshark`'s display filter (`-Y` option). You can find some examples from `https://tshark.dev/analyze/packet_hunting/packet_hunting/`.
* The `tshark_option` field in `config.json` can be used to configure `tshark` command, but typically it is not recommended to change the field value, since such change generates unexpected output results from the `tshark` command execution.
* The `fpnt_tshark_error_log` field in `config.json` specifies the name of `tshark`'s error log. If `fpnt` does not work correctly, it is recommended to check the error log file.
* When multiprocessing is turned on, storing all errors in a single error log file makes analysis more difficult. The `log_numbering_concurrency` field in `config.json` can be useful, as it generates multiple error log files tagged with their respective process IDs.
