cmake_minimum_required(VERSION 3.14...3.22)

project(FPNT_TARGET LANGUAGES CXX)

# --- Import tools ----

include(../cmake/tools.cmake)

# ---- Dependencies ----

include(../cmake/CPM.cmake)

CPMAddPackage(NAME FPNT SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/..)

# ---- Create standalone executable ----

file(GLOB sources CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/source/*.cpp)

add_executable(${PROJECT_NAME} ${sources})

set_target_properties(${PROJECT_NAME} PROPERTIES CXX_STANDARD 20 OUTPUT_NAME "fpnt")

target_link_libraries(${PROJECT_NAME} PRIVATE FPNT)
target_link_libraries(${PROJECT_NAME} PRIVATE fmt::fmt)
target_link_libraries(${PROJECT_NAME} PRIVATE csv)
target_link_libraries(${PROJECT_NAME} PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(${PROJECT_NAME} PRIVATE gcov) # csv requires gcov

target_include_directories(${PROJECT_NAME} PRIVATE ${CPM_PACKAGE_FPNT_SOURCE_DIR}/include)
target_include_directories(${PROJECT_NAME} PRIVATE ${CPM_PACKAGE_pstreams_SOURCE_DIR})
target_include_directories(${PROJECT_NAME} PRIVATE ${rang_SOURCE_DIR}/include)
target_include_directories(${PROJECT_NAME} PRIVATE ${nlohmann_json_SOURCE_DIR}/include)
target_include_directories(${PROJECT_NAME} PRIVATE ${CLI11_SOURCE_DIR}/include)
target_include_directories(${PROJECT_NAME} PRIVATE ${csv_SOURCE_DIR}/include)
target_include_directories(${PROJECT_NAME} INTERFACE ${fmt_INCLUDE_DIR})
