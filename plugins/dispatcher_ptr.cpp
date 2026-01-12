#include "dispatcher_ptr.h"

namespace fpnt {

  fpnt::Dispatcher *d;

  size_t get_idx(std::string key, std::string from, std::string to) {  // v0.3
    nlohmann::json *cnt_obj = &d->out[from][key];
    if (to == "eq" || from == to) {
      return (*cnt_obj)["__" + to + "_idx"].get<size_t>();
    }

    // chk_get_valid(from, to); 안 써도 됨
    if (d->g_lv_idx[from] > d->g_lv_idx[to]) {
      std::cerr << "please use get_idxs to access lower granuality records!" << std::endl;
      exit(1);
    }

    // now g_lv_idx[from] < g_lv_idx[to]
    return (*cnt_obj)["__" + to + "_idx"].get<size_t>();
  }

  /*
   */
  std::string get_key(std::string key, std::string from, std::string to) {  // v0.3
    nlohmann::json *cnt_obj = &d->out[from][key];
    if (to == "eq" || from == to) {
      return (*cnt_obj)["__" + to + "_key"].get<std::string>();
    }

    // chk_get_valid(from, to); 안 써도 됨
    if (d->g_lv_idx[from] > d->g_lv_idx[to]) {
      std::cerr << "please use get_idxs to access lower granuality records!" << std::endl;
      exit(1);
    }

    // now g_lv_idx[from] < g_lv_idx[to]
    return (*cnt_obj)["__" + to + "_key"].get<std::string>();
  }

  std::vector<size_t> get_idxs(std::string key, std::string from,
                               std::string to) {  // v0.3
    if (d->g_lv_idx[from] <= d->g_lv_idx[to]) {
      std::cerr << "please use get_idx to access higher granuality records!" << std::endl;
      exit(1);
    }

    // g_lv_idx[from] > g_lv_idx[to]
    std::vector<size_t> result;
    std::vector<std::string> cnt_child_keys = d->out_child_keys[from][key];
    for (auto &x : cnt_child_keys) {
      if (d->g_lv_idx[from] == d->g_lv_idx[to] + 1) {
        result.push_back(d->out_key2idx[to][x]);
      } else {
        std::vector<std::size_t> child_result = get_idxs(x, d->g_lvs[d->g_lv_idx[from] - 1], to);
        result.insert(result.end(), child_result.begin(), child_result.end());
      }
    }

    return result;
  }

  std::vector<std::string> get_keys(std::string key, std::string from,
                                    std::string to) {  // v0.3
    if (d->g_lv_idx[from] <= d->g_lv_idx[to]) {
      std::cerr << "please use get_idx to access higher granuality records!" << std::endl;
      exit(1);
    }

    // g_lv_idx[from] > g_lv_idx[to]
    std::vector<std::string> result;
    std::vector<std::string> cnt_child_keys = d->out_child_keys[from][key];
    for (auto &x : cnt_child_keys) {
      if (d->g_lv_idx[from] == d->g_lv_idx[to] + 1) {
        result.push_back(x);
      } else {
        std::vector<std::string> child_result = get_keys(x, d->g_lvs[d->g_lv_idx[from] - 1], to);
        result.insert(result.end(), child_result.begin(), child_result.end());
      }
    }
    return result;
  }

}  // namespace fpnt