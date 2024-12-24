#ifndef _UTIL_H
#define _UTIL_H

#include <utility>              // pair_splitter
#include <string>               // maybe the basic datatype in this program
#include <algorithm>
#include <sstream>              // pair_splitter
#include <vector>               // splitter
#include <iostream>             // cerr


#include <rang.hpp>             // ranbBout, rangBerr, rangout, rangerr

// inline helper functions for colored iostream
inline void rangBout(std::string s, rang::fg color) {
    std::cout << rang::style::bold << color << s << rang::style::reset << std::endl;
}

inline void rangBerr(std::string s, rang::fg color) {
    std::cerr << rang::style::bold << color << s << rang::style::reset << std::endl;
}

inline void rangout(std::string s, rang::fg color) {
    std::cout << color << s << rang::style::reset << std::endl;
}

inline void rangerr(std::string s, rang::fg color) {
    std::cerr << color << s << rang::style::reset << std::endl;
}


/**
 * the following code snippet is taken from Jan Schultke's answer
 * Licensed under: CC BY-SA 4.0 ( https://creativecommons.org/licenses/by-sa/4.0/ )
 * https://stackoverflow.com/questions/216823/how-to-trim-a-stdstring
 *  */ 

// trim from start (in place)
inline void ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
}

// trim from end (in place)
inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

// trim from both ends (in place)
inline void trim(std::string &s) {
    rtrim(s);
    ltrim(s);
}

// trim from start (copying)
inline std::string ltrim_copy(std::string s) {
    ltrim(s);
    return s;
}

// trim from end (copying)
inline std::string rtrim_copy(std::string s) {
    rtrim(s);
    return s;
}

// trim from both ends (copying)
inline std::string trim_copy(std::string s) {
    trim(s);
    return s;
}

// end of the stackoverflow code snippet

// inline helper functions for string split
inline std::pair<std::string, std::string> pair_split(const std::string& key, const char separator) {
    std::istringstream iss(key);
    std::string second;
    getline(iss, second, separator);
    std::string first = second;
    getline(iss, second, separator);
    return std::pair<std::string, std::string>(first, second);
}

inline std::vector<std::string> split(const std::string& str, const char separator) {
    std::vector<std::string> result;

    std::istringstream iss(str);
    std::string item;
    while (getline(iss, item, separator))
        result.push_back(item);

    return result;
}

inline std::vector<std::string> split_with_trim(const std::string& str, const std::string& delimiters, bool do_not_allow_empty = false) {
    std::vector<std::string> result;
    std::string::size_type lastPos = 0;
    std::string::size_type pos = str.find_first_of(delimiters, lastPos);

    while(std::string::npos != pos && std::string::npos != lastPos) {
        if (str.substr(lastPos, pos-lastPos) == "" && do_not_allow_empty) {
            std::cerr << "split_with_trim: do not allow empty error!" << std::endl;
            exit(1);
        } else
            result.push_back(str.substr(lastPos, pos-lastPos));
        lastPos = pos+1;
        pos = str.find_first_of(delimiters, lastPos);
    }

    if (str.substr(lastPos, pos-lastPos) == "" && do_not_allow_empty) {
        std::cerr << "split_with_trim: do not allow empty error!" << std::endl;
        exit(1);
    } else
       result.push_back(str.substr(lastPos, pos - lastPos));

    return result;
}

#endif