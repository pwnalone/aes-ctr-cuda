cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project(AesCudaCtr LANGUAGES CXX CUDA)

set(CMAKE_CXX_STANDARD 14)

include_directories(src)

enable_testing()
find_package(GTest)
if(GTEST_FOUND)
    add_subdirectory(test)
endif()

add_subdirectory(src)
