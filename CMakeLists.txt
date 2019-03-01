cmake_minimum_required (VERSION 2.6)
project(sntp)

enable_language(C)
enable_language(CXX)

set(CMAKE_C_FLAGS "-Wall -g")
set(sntp_SRCS sntp.c)
add_executable(sntp ${sntp_SRCS})
target_link_libraries(sntp pthread)
