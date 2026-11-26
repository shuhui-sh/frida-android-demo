cmake_minimum_required(VERSION 3.22.1)
project("reajiagu")

add_library(
    reajiagu
    SHARED
    native-lib.cpp
)

find_library(
    log-lib
    log
)

target_link_libraries(
    reajiagu
    ${log-lib}
)
