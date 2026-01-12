cmake_minimum_required(VERSION 3.14...3.22)
project(FPNT_PLUGINS_PROJECT LANGUAGES CXX)

file(GLOB FPNT_PLUGINS_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

# Generate Target
add_library(FPNT_PLUGINS SHARED ${FPNT_PLUGINS_SOURCES})
set_target_properties(FPNT_PLUGINS PROPERTIES CXX_STANDARD 20)
set_property(TARGET FPNT_PLUGINS PROPERTY POSITION_INDEPENDENT_CODE ON)
target_compile_options(FPNT_PLUGINS PRIVATE -Wno-error=unused-parameter)
target_compile_options(FPNT_PLUGINS PRIVATE -Wno-error=return-type-c-linkage)

# Linking dependencies (loaded from the parent project)
target_link_libraries(FPNT_PLUGINS PRIVATE FPNT nlohmann_json::nlohmann_json fmt::fmt csv)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  target_link_libraries(FPNT_PLUGINS PRIVATE gcov)
endif()

# Install settings: install in the same directory as the executable (fpnt)
install(
  TARGETS FPNT_PLUGINS
  LIBRARY DESTINATION .
  RUNTIME DESTINATION .
)
