cmake_minimum_required(VERSION 3.15)
project(ChatApp CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL with both libraries and headers
find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")

# Find termcap (used for raw terminal input/output on Linux)
find_library(TERMCAP_LIBRARY NAMES termcap tinfo curses ncurses)

# Compiler definitions
add_compile_options(-D_GNU_SOURCE)

# Common source files (shared between client & server)
# Include your new dh_utils.cpp here.
set(COMMON_SOURCES
    src/common.cpp
    src/crypto.cpp
    src/dh_utils.cpp
)

# Server and client source files
set(SERVER_SOURCES src/server/server.cpp)
set(CLIENT_SOURCES src/client/client.cpp)

# Add proto directory for Protocol Buffers

# Common library
add_library(common STATIC ${COMMON_SOURCES})
target_include_directories(common PUBLIC
    include
    ${OPENSSL_INCLUDE_DIR}
)
target_link_libraries(common PRIVATE 
    OpenSSL::Crypto
)

# Server executable
add_executable(chat-server ${SERVER_SOURCES})
target_include_directories(chat-server PRIVATE include)
target_link_libraries(chat-server PRIVATE 
    common
    pthread
)

# Client executable
add_executable(chat-client ${CLIENT_SOURCES})
target_include_directories(chat-client PRIVATE include)
target_link_libraries(chat-client PRIVATE 
    common
    pthread
    ${TERMCAP_LIBRARY}
    OpenSSL::Crypto
)

# Installation rule
install(TARGETS chat-server chat-client DESTINATION bin)
