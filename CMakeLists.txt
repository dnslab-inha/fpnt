cmake_minimum_required(VERSION 3.14...3.22)

# ---- Project ----

project(
  FPNT
  VERSION 0.3
  DESCRIPTION "FPNT: a flexible preprocessor framework for network traffic"
  LANGUAGES CXX
)

# If the install path is not specified, set it to fpnt_release in the user's home directory
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX
      "$ENV{HOME}/fpnt_release"
      CACHE PATH "Default install prefix" FORCE
  )
endif()

# https://stackoverflow.com/questions/58783805/define-debug-and-release-symbols-in-visual-studio-code
if(CMAKE_BUILD_TYPE STREQUAL "")
  # Build type is not set eg. command was "cmake .."
  message(STATUS "  Diag: Build type was unspecified, set to Release")
  set(CMAKE_BUILD_TYPE Release)
else()
  message(STATUS "  Diag: Build type specified as '${CMAKE_BUILD_TYPE}'")
endif()

if("${CMAKE_BUILD_TYPE}" STREQUAL Debug)
  set_directory_properties(PROPERTIES COMPILE_DEFINITIONS "_DEBUG")
else()
  set_directory_properties(PROPERTIES COMPILE_DEFINITIONS "NDEBUG")
endif()

# ---- Include guards ----

if(PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
  message(
    FATAL_ERROR
      "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there."
  )
endif()

# ---- Add dependencies via CPM ----
# see https://github.com/TheLartians/CPM.cmake for more info

include(cmake/CPM.cmake)

# PackageProject.cmake will be used to make our target installable
CPMAddPackage("gh:TheLartians/PackageProject.cmake@1.8.0")

include(cmake/dependencies.cmake)
# ---- Add source files ----

# Note: globbing sources is considered bad practice as CMake's generators may not detect new files
# automatically. Keep that in mind when changing files, or explicitly mention them here.
file(GLOB_RECURSE headers CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")
file(GLOB_RECURSE sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/source/*.cpp")

# ---- Create library ----

# Note: for header-only libraries change all PUBLIC flags to INTERFACE and create an interface
# target: add_library(${PROJECT_NAME} INTERFACE)
add_library(${PROJECT_NAME} ${headers} ${sources})
set_target_properties(${PROJECT_NAME} PROPERTIES CXX_STANDARD 20)
set_target_properties(${PROJECT_NAME} PROPERTIES POSITION_INDEPENDENT_CODE ON)

# being a cross-platform target, we enforce standards conformance on MSVC
target_compile_options(${PROJECT_NAME} PUBLIC "$<$<COMPILE_LANG_AND_ID:CXX,MSVC>:/permissive->")

# Link dependencies
link_libraries(--coverage)
target_link_libraries(${PROJECT_NAME} PUBLIC fmt::fmt)
target_link_libraries(${PROJECT_NAME} PUBLIC nlohmann_json::nlohmann_json)
target_link_libraries(${PROJECT_NAME} PUBLIC CLI11::CLI11)
target_link_libraries(${PROJECT_NAME} PUBLIC rang)
target_link_libraries(${PROJECT_NAME} PUBLIC csv)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  target_link_libraries(${PROJECT_NAME} PRIVATE gcov)
endif()
target_include_directories(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${PStreams_SOURCE_DIR}>)
target_include_directories(
  ${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
                         $<INSTALL_INTERFACE:include>
)

# ---- Create an installable target ----
# this allows users to install and find the library via `find_package()`. the location where the
# project's version header will be placed should match the project's regular header paths
string(TOLOWER ${PROJECT_NAME}/version.h VERSION_HEADER_LOCATION)

# Packaging Configuration via packageProject
include(GNUInstallDirs)
packageProject(
  NAME ${PROJECT_NAME}
  VERSION ${PROJECT_VERSION}
  BINARY_DIR ${PROJECT_BINARY_DIR}
  INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include
  INCLUDE_DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  COMPATIBILITY SameMajorVersion
  DEPENDENCIES fmt
  DEPENDENCIES nlohmann_json
  DEPENDENCIES CLI11
  DEPENDENCIES csv
)

# Install dfref directory (run crawler if missing) and config.json
install(
  CODE "
  set(DFREF_SRC \"${PROJECT_SOURCE_DIR}/dfref\")
  if(NOT EXISTS \"\${DFREF_SRC}\")
    message(STATUS \"dfref directory not found. Executing crawl_dfref.py...\")
    execute_process(
      COMMAND python3 \"${PROJECT_SOURCE_DIR}/crawl_dfref.py\"
      WORKING_DIRECTORY \"${PROJECT_SOURCE_DIR}\"
    )
  endif()
  if(EXISTS \"\${DFREF_SRC}\")
    file(COPY \"\${DFREF_SRC}\" DESTINATION \"\${CMAKE_INSTALL_PREFIX}\")
  endif()
"
)

install(FILES "${PROJECT_SOURCE_DIR}/config.json" DESTINATION .)
install(
  CODE "
  set(CONFIG_PATH \"\${CMAKE_INSTALL_PREFIX}/config.json\")
  if(EXISTS \"\${CONFIG_PATH}\")
    file(READ \"\${CONFIG_PATH}\" CONFIG_CONTENT)
    string(REGEX REPLACE \"\\\"plugins_path\\\": \\\"[^\\\"]*\\\"\" \"\\\"plugins_path\\\": \\\"./libFPNT_PLUGINS.so\\\"\" CONFIG_CONTENT \"\${CONFIG_CONTENT}\")
    file(WRITE \"\${CONFIG_PATH}\" \"\${CONFIG_CONTENT}\")
  endif()
"
)

# Install config_mta config sample directory
install(
  CODE "
  set(CONFIG_SAMPLE_SRC \"${PROJECT_SOURCE_DIR}/config_mta\")
  if(EXISTS \"\${CONFIG_SAMPLE_SRC}\")
    file(COPY \"\${CONFIG_SAMPLE_SRC}\" DESTINATION \"\${CMAKE_INSTALL_PREFIX}\")
  else()
    message(WARNING \"config_mta sample directory not found at \${CONFIG_SAMPLE_SRC}\")
  endif()
"
)

# Add subdirectories
add_subdirectory(standalone)
add_subdirectory(plugins)
