cmake_minimum_required(VERSION 3.16)

project(VulpineToolchain LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Add both the root directory and the src directory to the include path
# This ensures VS Code IntelliSense can resolve headers no matter where they sit
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Define the executable target using the main file inside src
add_executable(vkit
    src/main.cpp
    src/VDE.cpp
)

# Explicitly bind the include targets to the executable for the compiler
target_include_directories(vkit PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)