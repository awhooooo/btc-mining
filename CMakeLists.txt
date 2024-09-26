cmake_minimum_required(VERSION 3.19)

# Project name
project(miner)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add the src directory
include_directories(${PROJECT_SOURCE_DIR})

# Set Boost include and library directories
set(BOOST_ROOT "/Users/legacy/C++_bitcoin/installation_prefix")
set(BOOST_NO_SYSTEM_PATHS TRUE)
set(BOOST_INCLUDEDIR "/Users/legacy/C++_bitcoin/installation_prefix/include")
set(BOOST_LIBRARYDIR "/Users/legacy/C++_bitcoin/installation_prefix/lib")

# Find Boost with specific components
find_package(Boost 1.73 REQUIRED)

# Find Boost system library
find_library(Boost_SYSTEM_LIBRARIES
    NAMES boost_system
    HINTS /Users/legacy/C++_bitcoin/installation_prefix/lib
)

# Find Boost regex library
find_library(Boost_REGEX_LIBRARIES
    NAMES boost_regex
    HINTS /Users/legacy/C++_bitcoin/installation_prefix/lib
)

# Find Boost thread library
find_library(Boost_THREAD_LIBRARIES
    NAMES boost_thread
    HINTS /Users/legacy/C++_bitcoin/installation_prefix/lib
)

# Find Boost program_options library
find_library(Boost_PROGRAM_OPTIONS_LIBRARIES
    NAMES boost_program_options
    HINTS /Users/legacy/C++_bitcoin/installation_prefix/lib
)
    
# Find the libraries installed via Homebrew
find_library(L_SPDLOG spdlog HINTS /opt/homebrew/Cellar/spdlog/1.14.1/lib)
find_library(L_FMT fmt HINTS /opt/homebrew/Cellar/fmt/10.2.1_1/lib)
find_library(L_JSONCPP jsoncpp HINTS /opt/homebrew/Cellar/json/1.9.5/lib)
find_library(L_JSONRPC_CPP_CLIENT jsonrpccpp-client HINTS /opt/homebrew/Cellar/libjson-rpc-cpp/1.4.1_2/lib)
find_library(L_JSONRPC_CPP_COMMON jsonrpccpp-common HINTS /opt/homebrew/Cellar/libjson-rpc-cpp/1.4.1_2/lib)
find_library(L_JSONRPC_CPP_SERVER jsonrpccpp-server HINTS /opt/homebrew/Cellar/libjson-rpc-cpp/1.4.1_2/lib)
find_library(L_JSONRPC_CPP_STUB jsonrpccpp-stub HINTS /opt/homebrew/Cellar/libjson-rpc-cpp/1.4.1_2/lib)
find_library(L_BITCOIN_SYSTEM bitcoin-system HINTS /Users/legacy/C++_bitcoin/installation_prefix/lib)
find_library(L_SECP256K1 secp256k1 HINTS /Users/legacy/C++_bitcoin/installation_prefix/lib)

message(STATUS "Boost_FOUND: ${Boost_FOUND}")
message(STATUS "Boost_INCLUDE_DIRS: ${Boost_INCLUDE_DIRS}")
message(STATUS "Boost_LIBRARIES: ${Boost_LIBRARIES}")
message(STATUS "L_SPDLOG: ${L_SPDLOG}")
message(STATUS "L_FMT: ${L_FMT}")
message(STATUS "L_JSONCPP: ${L_JSONCPP}")
message(STATUS "L_JSONRPC_CPP_CLIENT: ${L_JSONRPC_CPP_CLIENT}")
message(STATUS "L_JSONRPC_CPP_COMMON: ${L_JSONRPC_CPP_COMMON}")
message(STATUS "L_JSONRPC_CPP_SERVER: ${L_JSONRPC_CPP_SERVER}")
message(STATUS "L_JSONRPC_CPP_STUB: ${L_JSONRPC_CPP_STUB}")
message(STATUS "L_LIBBITCOIN_SYSEM: ${L_BITCOIN_SYSTEM}")
message(STATUS "L_SECP256K1_LIB: ${L_SECP256K1}")

# Source files
set(SOURCES
    src/arguments.cpp
    src/bech32.cpp
    src/bitcoinrpc.cpp
    src/coinbase.cpp
    src/calculation.cpp
    src/segwit_addr.cpp
    main.cpp
)

# Header files (not strictly necessary for CMake, but good for organization)
set(HEADERS
    include/arguments.hpp
    include/bitcoinrpc.hpp
    include/bech32.hpp
    include/coinbase.hpp
    include/calculation.hpp
    include/exceptions.hpp
    include/types.hpp
    include/segwit_addr.hpp
)

# Add the executable
add_executable(miner ${SOURCES} ${HEADERS})

# Link the libraries
target_link_libraries(miner PRIVATE
    ${Boost_LIBRARIES}
    ${Boost_SYSTEM_LIBRARIES}
    ${Boost_REGEX_LIBRARIES}
    ${Boost_THREAD_LIBRARIES}
    ${Boost_PROGRAM_OPTIONS_LIBRARIES}
    ${L_SPDLOG}
    ${L_FMT}
    ${L_JSONCPP}
    ${L_JSONRPC_CPP_CLIENT}
    ${L_JSONRPC_CPP_COMMON}
    ${L_JSONRPC_CPP_SERVER}
    ${L_JSONRPC_CPP_STUB}
    ${L_BITCOIN_SYSTEM}
    ${L_SECP256K1}
)

# Set the include directories for the libraries
target_include_directories(miner PRIVATE
    /opt/homebrew/Cellar/nlohmann-json/3.11.3/include
    /opt/homebrew/Cellar/spdlog/1.14.1/include
    /opt/homebrew/Cellar/fmt/10.2.1_1/include
    /opt/homebrew/Cellar/json/1.9.5/include
    /opt/homebrew/Cellar/libjson-rpc-cpp/1.4.1_2/include
    /opt/homebrew/opt
    /Users/legacy/C++_bitcoin/installation_prefix/include
    ${Boost_INCLUDE_DIRS}
)

target_compile_options(miner PRIVATE -Wno-deprecated)

# Set the RPATH for runtime library loading
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_INSTALL_RPATH "/opt/homebrew/lib")