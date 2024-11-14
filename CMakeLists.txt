cmake_minimum_required(VERSION 3.29)
project(redpoint C)

set(CMAKE_C_STANDARD 17)

add_executable(redpoint
        src/main.c
)

add_custom_command(TARGET redpoint POST_BUILD
        COMMAND codesign --force --deep -s - $<TARGET_FILE:redpoint>
        COMMENT "Ad-hoc signing redpoint"
)

target_link_libraries(redpoint PRIVATE proc)