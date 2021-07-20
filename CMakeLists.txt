cmake_minimum_required(VERSION 3.16)

project(tfhe-protocol C CXX)

## Use -std=c++11 as default.
set(CMAKE_C_STANDARD 11)


link_directories(/usr/local/lib)
add_library(tfhe SHARED IMPORTED)
set_property(TARGET tfhe PROPERTY IMPORTED_LOCATION "/usr/local/lib/libtfhe-nayuki-portable.so")
include_directories(/usr/local/include/tfhe)

add_executable(THREATS src/Client.cpp include/Client.h src/Math.cpp include/Math.h src/main.cpp)
target_link_libraries(THREATS tfhe)

