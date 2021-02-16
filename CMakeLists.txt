cmake_minimum_required(VERSION 3.16)

project(tfhe-protocol C CXX)

## Use -std=c++11 as default.
set(CMAKE_C_STANDARD 11)

## Use -std=c++14 as default.
#set(CMAKE_CXX_STANDARD 14)



link_directories(/usr/local/lib)
add_library(tfhe SHARED IMPORTED)
set_property(TARGET tfhe PROPERTY IMPORTED_LOCATION "/usr/local/lib/libtfhe-nayuki-portable.so")
include_directories(/usr/local/include/tfhe)

#find_library(NTL_LIB ntl)
#if(NOT NTL_LIB)
#    message(FATAL_ERROR "ntl library not found.  Rerun cmake with -DCMAKE_PREFIX_PATH=\"<path to lib1>;<path to lib2>\"")
#endif()
#find_library(GMP_LIB gmp)
#if(NOT GMP_LIB)
#    message(FATAL_ERROR "ntl library not found.  Rerun cmake with -DCMAKE_PREFIX_PATH=\"<path to lib1>;<path to lib2>\"")
#endif()



add_executable(test src/test.cpp)
target_link_libraries(test tfhe)

add_executable(Client src/Client.cpp include/Client.h src/Math.cpp include/Math.h)
target_link_libraries(Client tfhe)

add_executable(test_dinn src/test_dinn.cpp include/Client.h)
target_link_libraries(test_dinn tfhe)

