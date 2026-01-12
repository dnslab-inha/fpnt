cmake_minimum_required(VERSION 3.14...3.22)

project(FPNT_STANDALONE LANGUAGES CXX)

file(GLOB sources CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/source/*.cpp)

add_executable(fpnt_bin ${sources})
set_target_properties(
  fpnt_bin PROPERTIES CXX_STANDARD 20 OUTPUT_NAME "fpnt" INSTALL_RPATH "$ORIGIN"
)

target_link_libraries(fpnt_bin PRIVATE FPNT fmt::fmt csv nlohmann_json::nlohmann_json)

install(TARGETS fpnt_bin RUNTIME DESTINATION .)

# Attempt to create a symbolic link in the system path (/usr/local/bin) after installation
install(
  CODE "
    set(FPNT_EXEC \"\${CMAKE_INSTALL_PREFIX}/fpnt\")
    set(LINK_PATH \"/usr/local/bin/fpnt\")
    message(STATUS \"Attempting to create symbolic link: \${LINK_PATH} -> \${FPNT_EXEC}\")
    execute_process(COMMAND ln -sf \"\${FPNT_EXEC}\" \"\${LINK_PATH}\" RESULT_VARIABLE LN_RES ERROR_QUIET)
    if(NOT LN_RES EQUAL 0)
        message(WARNING \"Failed to create symbolic link at \${LINK_PATH}. Please add \${CMAKE_INSTALL_PREFIX} to your PATH or run install with sudo.\")
    endif()
"
)
