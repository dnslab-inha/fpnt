cmake_minimum_required(VERSION 3.14...3.22)

project(FPNT_PLUGINS LANGUAGES CXX)

# --- Import tools ----

include(../cmake/tools.cmake)

# ---- Dependencies ----

include(../cmake/CPM.cmake)

FetchContent_Declare(fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG master
)
FetchContent_MakeAvailable(fmt)
set_property(TARGET fmt PROPERTY POSITION_INDEPENDENT_CODE ON)

CPMAddPackage("gh:nlohmann/json#master") # CMakeLists.txt available; nlohmann_json
CPMAddPackage("gh:jwakely/pstreams#master")
CPMAddPackage("gh:CLIUtils/CLI11#main")
CPMAddPackage("gh:agauniyal/rang#master")
CPMAddPackage("gh:vincentlaucsb/csv-parser#master")



if(PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
  message(
    FATAL_ERROR
      "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there."
  )
endif()

#CPMAddPackage(NAME FPNT SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/..)

file(GLOB FPNT_PLUGINS_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

add_library(FPNT_PLUGINS SHARED ${FPNT_PLUGINS_SOURCES})

# option(BUILD_SHARED_LIBS "Build using shared libraries" ON) # to make shared libraries it is required
# if (BUILD_SHARED_LIBS)
#    set_property(TARGET FPNT_PLUGINS PROPERTY POSITION_INDEPENDENT_CODE ON)  
# endif()
set_property(TARGET FPNT_PLUGINS PROPERTY POSITION_INDEPENDENT_CODE ON)

#target_link_libraries(${PROJECT_NAME} INTERFACE FPNT)
target_include_directories(${PROJECT_NAME} PRIVATE ${nlohmann_json_SOURCE_DIR}/include)
target_include_directories(${PROJECT_NAME} PRIVATE ${fmt_INCLUDE_DIR})
target_include_directories(${PROJECT_NAME} PRIVATE ${csv_SOURCE_DIR}/include)
target_include_directories(${PROJECT_NAME} PRIVATE ${CPM_PACKAGE_pstreams_SOURCE_DIR})
target_include_directories(${PROJECT_NAME} PRIVATE ${rang_SOURCE_DIR}/include)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_DL_LIBS})
target_include_directories(${PROJECT_NAME} PRIVATE ${CPM_PACKAGE_FPNT_SOURCE_DIR}/include)
target_compile_definitions(${PROJECT_NAME} PRIVATE _GNU_SOURCE)

target_link_libraries(${PROJECT_NAME} PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(${PROJECT_NAME} PRIVATE fmt::fmt)
target_link_libraries(${PROJECT_NAME} INTERFACE csv)
target_link_libraries(${PROJECT_NAME} PRIVATE gcov) # csv reqires gcov library

set_target_properties(${PROJECT_NAME} PROPERTIES CXX_STANDARD 20)
