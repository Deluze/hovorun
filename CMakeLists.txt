cmake_minimum_required(VERSION 3.30)

project(hovorun_server LANGUAGES CXX)

# C++26 (std::expected, std::print, deducing this, ranges::to, ...). The standard flag is set per target below
# instead of CMAKE_CXX_STANDARD 26: CMake 3.30 (bundled with CLion 2024.2) has no C++26 flag for MSVC, and a
# global setting also breaks CMake's own try_compile checks such as FindThreads.
set(CMAKE_CXX_EXTENSIONS OFF)

# Standalone Asio (no Boost). Prefer an installed package (e.g. vcpkg "asio"), otherwise fetch the headers.
find_package(asio CONFIG QUIET)

if (NOT asio_FOUND)
    include(FetchContent)
    FetchContent_Declare(
            asio
            GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
            GIT_TAG asio-1-30-2
            GIT_SHALLOW TRUE
    )
    # The asio repo has no top-level CMakeLists.txt, so this only downloads the headers.
    FetchContent_MakeAvailable(asio)

    add_library(asio INTERFACE)
    add_library(asio::asio ALIAS asio)
    target_include_directories(asio INTERFACE ${asio_SOURCE_DIR}/asio/include)
    target_compile_definitions(asio INTERFACE ASIO_STANDALONE ASIO_NO_DEPRECATED)
endif ()

find_package(Threads REQUIRED)

file(GLOB_RECURSE HOVORUN_SOURCES CONFIGURE_DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/*.hpp)

add_executable(hovorun_server ${HOVORUN_SOURCES})

target_include_directories(hovorun_server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(hovorun_server PRIVATE asio::asio Threads::Threads)

if (WIN32)
    # Asio needs these on Windows; _WIN32_WINNT 0x0601 = Windows 7 API level.
    target_compile_definitions(hovorun_server PRIVATE _WIN32_WINNT=0x0601 WIN32_LEAN_AND_MEAN NOMINMAX)
    target_link_libraries(hovorun_server PRIVATE ws2_32 mswsock)
endif ()

if (MSVC)
    # /std:c++latest is MSVC's C++26 (working draft) mode. /Zc:__cplusplus reports the real version.
    target_compile_options(hovorun_server PRIVATE /std:c++latest /Zc:__cplusplus /W4 /permissive- /utf-8)
else ()
    # c++2c = C++26 working draft (GCC 14+, Clang 17+).
    target_compile_options(hovorun_server PRIVATE -std=c++2c -Wall -Wextra)
endif ()

# Copy the default config next to the binary so the server runs out of the build folder.
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config/server.ini ${CMAKE_CURRENT_BINARY_DIR}/server.ini COPYONLY)

# `cmake --install` lays out a runnable release folder: binary, default config, README.
install(TARGETS hovorun_server RUNTIME DESTINATION .)
install(FILES config/server.ini README.md DESTINATION .)
