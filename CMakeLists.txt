cmake_minimum_required(VERSION 3.14...3.22)

# ---- Project ----

project(
  FPNT
  VERSION 0.3
  DESCRIPTION "FPNT: a flexible preprocessor framework for network traffic"
  LANGUAGES CXX
)

# https://stackoverflow.com/questions/58783805/define-debug-and-release-symbols-in-visual-studio-code
if (CMAKE_BUILD_TYPE STREQUAL "")
    # Build type is not set eg. command was "cmake .."
    message(STATUS "  Diag: Build type was unspecified, set to Release")
    set(CMAKE_BUILD_TYPE Release)
else ()
    message(STATUS "  Diag: Build type specified as '${CMAKE_BUILD_TYPE}'")
endif ()

if (${CMAKE_BUILD_TYPE} STREQUAL Debug)
    set_directory_properties(PROPERTIES COMPILE_DEFINITIONS "_DEBUG")
else ()
    set_directory_properties(PROPERTIES COMPILE_DEFINITIONS "NDEBUG")
endif ()

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

# being a cross-platform target, we enforce standards conformance on MSVC
target_compile_options(${PROJECT_NAME} PUBLIC "$<$<COMPILE_LANG_AND_ID:CXX,MSVC>:/permissive->")

# Link dependencies
target_link_libraries(${PROJECT_NAME} PRIVATE fmt::fmt)
# target_link_libraries(${PROJECT_NAME} PRIVATE csv)
# target_link_libraries(${PROJECT_NAME} PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(${PROJECT_NAME} PRIVATE gcov) # csv requires gcov

target_include_directories(${PROJECT_NAME} PRIVATE ${CPM_PACKAGE_pstreams_SOURCE_DIR})
target_include_directories(${PROJECT_NAME} PRIVATE ${rang_SOURCE_DIR}/include)
target_include_directories(${PROJECT_NAME} PRIVATE ${nlohmann_json_SOURCE_DIR}/include)
target_include_directories(${PROJECT_NAME} PRIVATE ${CLI11_SOURCE_DIR}/include)
target_include_directories(${PROJECT_NAME} PRIVATE ${csv_SOURCE_DIR}/include)
target_include_directories(${PROJECT_NAME} INTERFACE ${fmt_INCLUDE_DIR})

target_include_directories(
  ${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
                         $<INSTALL_INTERFACE:include/${PROJECT_NAME}-${PROJECT_VERSION}>
)

# ---- Create an installable target ----
# this allows users to install and find the library via `find_package()`.
# the location where the project's version header will be placed should match the project's regular
# header paths
string(TOLOWER ${PROJECT_NAME}/version.h VERSION_HEADER_LOCATION)

# packageProject(
#   NAME ${PROJECT_NAME}
#   VERSION ${PROJECT_VERSION}
#   NAMESPACE ${PROJECT_NAME}
#   BINARY_DIR ${PROJECT_BINARY_DIR}
#   INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include
#   INCLUDE_DESTINATION include/${PROJECT_NAME}-${PROJECT_VERSION}
#   VERSION_HEADER "${VERSION_HEADER_LOCATION}"
#   COMPATIBILITY SameMajorVersion
#   DEPENDENCIES "nlohmann_json >= 3.11.3, csv >= 2.3.0, gcov"
# )