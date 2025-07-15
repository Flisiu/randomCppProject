include(cmake/SystemLink.cmake)
include(cmake/LibFuzzer.cmake)
include(CMakeDependentOption)
include(CheckCXXCompilerFlag)


include(CheckCXXSourceCompiles)


macro(randomCppProject_supports_sanitizers)
  if((CMAKE_CXX_COMPILER_ID MATCHES ".*Clang.*" OR CMAKE_CXX_COMPILER_ID MATCHES ".*GNU.*") AND NOT WIN32)

    message(STATUS "Sanity checking UndefinedBehaviorSanitizer, it should be supported on this platform")
    set(TEST_PROGRAM "int main() { return 0; }")

    # Check if UndefinedBehaviorSanitizer works at link time
    set(CMAKE_REQUIRED_FLAGS "-fsanitize=undefined")
    set(CMAKE_REQUIRED_LINK_OPTIONS "-fsanitize=undefined")
    check_cxx_source_compiles("${TEST_PROGRAM}" HAS_UBSAN_LINK_SUPPORT)

    if(HAS_UBSAN_LINK_SUPPORT)
      message(STATUS "UndefinedBehaviorSanitizer is supported at both compile and link time.")
      set(SUPPORTS_UBSAN ON)
    else()
      message(WARNING "UndefinedBehaviorSanitizer is NOT supported at link time.")
      set(SUPPORTS_UBSAN OFF)
    endif()
  else()
    set(SUPPORTS_UBSAN OFF)
  endif()

  if((CMAKE_CXX_COMPILER_ID MATCHES ".*Clang.*" OR CMAKE_CXX_COMPILER_ID MATCHES ".*GNU.*") AND WIN32)
    set(SUPPORTS_ASAN OFF)
  else()
    if (NOT WIN32)
      message(STATUS "Sanity checking AddressSanitizer, it should be supported on this platform")
      set(TEST_PROGRAM "int main() { return 0; }")

      # Check if AddressSanitizer works at link time
      set(CMAKE_REQUIRED_FLAGS "-fsanitize=address")
      set(CMAKE_REQUIRED_LINK_OPTIONS "-fsanitize=address")
      check_cxx_source_compiles("${TEST_PROGRAM}" HAS_ASAN_LINK_SUPPORT)

      if(HAS_ASAN_LINK_SUPPORT)
        message(STATUS "AddressSanitizer is supported at both compile and link time.")
        set(SUPPORTS_ASAN ON)
      else()
        message(WARNING "AddressSanitizer is NOT supported at link time.")
        set(SUPPORTS_ASAN OFF)
      endif()
    else()
      set(SUPPORTS_ASAN ON)
    endif()
  endif()
endmacro()

macro(randomCppProject_setup_options)
  option(randomCppProject_ENABLE_HARDENING "Enable hardening" ON)
  option(randomCppProject_ENABLE_COVERAGE "Enable coverage reporting" OFF)
  cmake_dependent_option(
    randomCppProject_ENABLE_GLOBAL_HARDENING
    "Attempt to push hardening options to built dependencies"
    ON
    randomCppProject_ENABLE_HARDENING
    OFF)

  randomCppProject_supports_sanitizers()

  if(NOT PROJECT_IS_TOP_LEVEL OR randomCppProject_PACKAGING_MAINTAINER_MODE)
    option(randomCppProject_ENABLE_IPO "Enable IPO/LTO" OFF)
    option(randomCppProject_WARNINGS_AS_ERRORS "Treat Warnings As Errors" OFF)
    option(randomCppProject_ENABLE_USER_LINKER "Enable user-selected linker" OFF)
    option(randomCppProject_ENABLE_SANITIZER_ADDRESS "Enable address sanitizer" OFF)
    option(randomCppProject_ENABLE_SANITIZER_LEAK "Enable leak sanitizer" OFF)
    option(randomCppProject_ENABLE_SANITIZER_UNDEFINED "Enable undefined sanitizer" OFF)
    option(randomCppProject_ENABLE_SANITIZER_THREAD "Enable thread sanitizer" OFF)
    option(randomCppProject_ENABLE_SANITIZER_MEMORY "Enable memory sanitizer" OFF)
    option(randomCppProject_ENABLE_UNITY_BUILD "Enable unity builds" OFF)
    option(randomCppProject_ENABLE_CLANG_TIDY "Enable clang-tidy" OFF)
    option(randomCppProject_ENABLE_CPPCHECK "Enable cpp-check analysis" OFF)
    option(randomCppProject_ENABLE_PCH "Enable precompiled headers" OFF)
    option(randomCppProject_ENABLE_CACHE "Enable ccache" OFF)
  else()
    option(randomCppProject_ENABLE_IPO "Enable IPO/LTO" ON)
    option(randomCppProject_WARNINGS_AS_ERRORS "Treat Warnings As Errors" ON)
    option(randomCppProject_ENABLE_USER_LINKER "Enable user-selected linker" OFF)
    option(randomCppProject_ENABLE_SANITIZER_ADDRESS "Enable address sanitizer" ${SUPPORTS_ASAN})
    option(randomCppProject_ENABLE_SANITIZER_LEAK "Enable leak sanitizer" OFF)
    option(randomCppProject_ENABLE_SANITIZER_UNDEFINED "Enable undefined sanitizer" ${SUPPORTS_UBSAN})
    option(randomCppProject_ENABLE_SANITIZER_THREAD "Enable thread sanitizer" OFF)
    option(randomCppProject_ENABLE_SANITIZER_MEMORY "Enable memory sanitizer" OFF)
    option(randomCppProject_ENABLE_UNITY_BUILD "Enable unity builds" OFF)
    option(randomCppProject_ENABLE_CLANG_TIDY "Enable clang-tidy" ON)
    option(randomCppProject_ENABLE_CPPCHECK "Enable cpp-check analysis" ON)
    option(randomCppProject_ENABLE_PCH "Enable precompiled headers" OFF)
    option(randomCppProject_ENABLE_CACHE "Enable ccache" ON)
  endif()

  if(NOT PROJECT_IS_TOP_LEVEL)
    mark_as_advanced(
      randomCppProject_ENABLE_IPO
      randomCppProject_WARNINGS_AS_ERRORS
      randomCppProject_ENABLE_USER_LINKER
      randomCppProject_ENABLE_SANITIZER_ADDRESS
      randomCppProject_ENABLE_SANITIZER_LEAK
      randomCppProject_ENABLE_SANITIZER_UNDEFINED
      randomCppProject_ENABLE_SANITIZER_THREAD
      randomCppProject_ENABLE_SANITIZER_MEMORY
      randomCppProject_ENABLE_UNITY_BUILD
      randomCppProject_ENABLE_CLANG_TIDY
      randomCppProject_ENABLE_CPPCHECK
      randomCppProject_ENABLE_COVERAGE
      randomCppProject_ENABLE_PCH
      randomCppProject_ENABLE_CACHE)
  endif()

  randomCppProject_check_libfuzzer_support(LIBFUZZER_SUPPORTED)
  if(LIBFUZZER_SUPPORTED AND (randomCppProject_ENABLE_SANITIZER_ADDRESS OR randomCppProject_ENABLE_SANITIZER_THREAD OR randomCppProject_ENABLE_SANITIZER_UNDEFINED))
    set(DEFAULT_FUZZER ON)
  else()
    set(DEFAULT_FUZZER OFF)
  endif()

  option(randomCppProject_BUILD_FUZZ_TESTS "Enable fuzz testing executable" ${DEFAULT_FUZZER})

endmacro()

macro(randomCppProject_global_options)
  if(randomCppProject_ENABLE_IPO)
    include(cmake/InterproceduralOptimization.cmake)
    randomCppProject_enable_ipo()
  endif()

  randomCppProject_supports_sanitizers()

  if(randomCppProject_ENABLE_HARDENING AND randomCppProject_ENABLE_GLOBAL_HARDENING)
    include(cmake/Hardening.cmake)
    if(NOT SUPPORTS_UBSAN 
       OR randomCppProject_ENABLE_SANITIZER_UNDEFINED
       OR randomCppProject_ENABLE_SANITIZER_ADDRESS
       OR randomCppProject_ENABLE_SANITIZER_THREAD
       OR randomCppProject_ENABLE_SANITIZER_LEAK)
      set(ENABLE_UBSAN_MINIMAL_RUNTIME FALSE)
    else()
      set(ENABLE_UBSAN_MINIMAL_RUNTIME TRUE)
    endif()
    message("${randomCppProject_ENABLE_HARDENING} ${ENABLE_UBSAN_MINIMAL_RUNTIME} ${randomCppProject_ENABLE_SANITIZER_UNDEFINED}")
    randomCppProject_enable_hardening(randomCppProject_options ON ${ENABLE_UBSAN_MINIMAL_RUNTIME})
  endif()
endmacro()

macro(randomCppProject_local_options)
  if(PROJECT_IS_TOP_LEVEL)
    include(cmake/StandardProjectSettings.cmake)
  endif()

  add_library(randomCppProject_warnings INTERFACE)
  add_library(randomCppProject_options INTERFACE)

  include(cmake/CompilerWarnings.cmake)
  randomCppProject_set_project_warnings(
    randomCppProject_warnings
    ${randomCppProject_WARNINGS_AS_ERRORS}
    ""
    ""
    ""
    "")

  if(randomCppProject_ENABLE_USER_LINKER)
    include(cmake/Linker.cmake)
    randomCppProject_configure_linker(randomCppProject_options)
  endif()

  include(cmake/Sanitizers.cmake)
  randomCppProject_enable_sanitizers(
    randomCppProject_options
    ${randomCppProject_ENABLE_SANITIZER_ADDRESS}
    ${randomCppProject_ENABLE_SANITIZER_LEAK}
    ${randomCppProject_ENABLE_SANITIZER_UNDEFINED}
    ${randomCppProject_ENABLE_SANITIZER_THREAD}
    ${randomCppProject_ENABLE_SANITIZER_MEMORY})

  set_target_properties(randomCppProject_options PROPERTIES UNITY_BUILD ${randomCppProject_ENABLE_UNITY_BUILD})

  if(randomCppProject_ENABLE_PCH)
    target_precompile_headers(
      randomCppProject_options
      INTERFACE
      <vector>
      <string>
      <utility>)
  endif()

  if(randomCppProject_ENABLE_CACHE)
    include(cmake/Cache.cmake)
    randomCppProject_enable_cache()
  endif()

  include(cmake/StaticAnalyzers.cmake)
  if(randomCppProject_ENABLE_CLANG_TIDY)
    randomCppProject_enable_clang_tidy(randomCppProject_options ${randomCppProject_WARNINGS_AS_ERRORS})
  endif()

  if(randomCppProject_ENABLE_CPPCHECK)
    randomCppProject_enable_cppcheck(${randomCppProject_WARNINGS_AS_ERRORS} "" # override cppcheck options
    )
  endif()

  if(randomCppProject_ENABLE_COVERAGE)
    include(cmake/Tests.cmake)
    randomCppProject_enable_coverage(randomCppProject_options)
  endif()

  if(randomCppProject_WARNINGS_AS_ERRORS)
    check_cxx_compiler_flag("-Wl,--fatal-warnings" LINKER_FATAL_WARNINGS)
    if(LINKER_FATAL_WARNINGS)
      # This is not working consistently, so disabling for now
      # target_link_options(randomCppProject_options INTERFACE -Wl,--fatal-warnings)
    endif()
  endif()

  if(randomCppProject_ENABLE_HARDENING AND NOT randomCppProject_ENABLE_GLOBAL_HARDENING)
    include(cmake/Hardening.cmake)
    if(NOT SUPPORTS_UBSAN 
       OR randomCppProject_ENABLE_SANITIZER_UNDEFINED
       OR randomCppProject_ENABLE_SANITIZER_ADDRESS
       OR randomCppProject_ENABLE_SANITIZER_THREAD
       OR randomCppProject_ENABLE_SANITIZER_LEAK)
      set(ENABLE_UBSAN_MINIMAL_RUNTIME FALSE)
    else()
      set(ENABLE_UBSAN_MINIMAL_RUNTIME TRUE)
    endif()
    randomCppProject_enable_hardening(randomCppProject_options OFF ${ENABLE_UBSAN_MINIMAL_RUNTIME})
  endif()

endmacro()
