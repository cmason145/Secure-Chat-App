cmake_minimum_required(VERSION 3.15)
project(ChatApp CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find termcap library
find_library(TERMCAP_LIBRARY NAMES termcap tinfo curses ncurses)

# Compiler definitions
add_compile_options(-D_GNU_SOURCE)

# Source files
set(COMMON_SOURCES src/common.cpp)
set(SERVER_SOURCES src/server/server.cpp)
set(CLIENT_SOURCES src/client/client.cpp)

# Executable targets
add_library(common STATIC ${COMMON_SOURCES})

add_executable(chat-server
    ${SERVER_SOURCES}
)

add_executable(chat-client
    ${CLIENT_SOURCES}
)

# Include directories
target_include_directories(common PUBLIC include)
target_include_directories(chat-server PRIVATE include)
target_include_directories(chat-client PRIVATE include)

# Link libraries
target_link_libraries(chat-server
    PRIVATE 
    common 
    pthread
)

target_link_libraries(chat-client
    PRIVATE 
    common 
    pthread
    ${TERMCAP_LIBRARY}  # Link termcap library
)

# Installation (optional)
install(TARGETS chat-server chat-client DESTINATION bin)