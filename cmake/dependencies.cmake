
# How to add Libraries using CPM's CPMAddPackage
# Examples
# CPMAddPackage("gh:vincentlaucsb/csv-parser#2.2.1") # csv-parser does not use version (prefix 'v' is added in tag) in their repository
# CPMAddPackage("gh:CLIUtils/CLI11@2.3.2") # CLI11 uses the version prefix in their repository
# gh: github,  @ version, # tag

#CPMAddPackage("gh:fmtlib/fmt#master")
#CPMAddPackage("gh:fmtlib/fmt#12.0.0")

set(FMT_INSTALL ON CACHE BOOL "" FORCE)
FetchContent_Declare(fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG master
)
FetchContent_MakeAvailable(fmt)
set_property(TARGET fmt PROPERTY POSITION_INDEPENDENT_CODE ON)

set(JSON_Install ON CACHE BOOL "" FORCE)
CPMAddPackage("gh:nlohmann/json#master") # CMakeLists.txt available; nlohmann_json

CPMAddPackage(
  NAME PStreams
  GITHUB_REPOSITORY jwakely/pstreams
  GIT_TAG master
  OPTIONS "PSTREAMS_INSTALL OFF"
)

if(TARGET PStreams)
 install(TARGETS PStreams EXPORT FPNTTargets)
 install(DIRECTORY ${PStreams_SOURCE_DIR}/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif()



CPMAddPackage(
  NAME CLI11
  GITHUB_REPOSITORY CLIUtils/CLI11
  GIT_TAG main
  OPTIONS "CLI11_INSTALL OFF"
)
if(TARGET CLI11)
 install(TARGETS CLI11 EXPORT FPNTTargets)
 install(DIRECTORY ${CLI11_SOURCE_DIR}/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif()

CPMAddPackage("gh:agauniyal/rang#master")
if(TARGET rang)
 install(TARGETS rang EXPORT FPNTTargets)
 install(DIRECTORY ${rang_SOURCE_DIR}/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif()

CPMAddPackage(
  NAME csv
  GITHUB_REPOSITORY vincentlaucsb/csv-parser
  GIT_TAG master
  OPTIONS "CSV_INSTALL OFF"
)
if(TARGET csv)
  # 1. 기존의 잘못된 인터페이스 포함 경로를 초기화합니다.
  set_target_properties(csv PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "")
  set_target_properties(csv PROPERTIES POSITION_INDEPENDENT_CODE ON)

  # 2. BUILD_INTERFACE 제너레이터 표현식을 사용하여 경로를 다시 설정합니다.
  # 이렇게 하면 CMake가 '빌드 시에만 쓰는 경로'임을 인지하여 에러를 내지 않습니다.
  target_include_directories(csv INTERFACE 
      $<BUILD_INTERFACE:${csv_SOURCE_DIR}/include>
      $<BUILD_INTERFACE:${csv_SOURCE_DIR}/include/internal>
  )
  install(TARGETS csv EXPORT FPNTTargets)
  install(DIRECTORY ${csv_SOURCE_DIR}/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif()
