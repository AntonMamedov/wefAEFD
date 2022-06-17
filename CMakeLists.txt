cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

project("proxy-exec linux kernel module" VERSION 0.1.0 LANGUAGES C)
set(CMAKE_C_STANDARD 90)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find kernel headers
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
find_package(KernelHeaders REQUIRED)


# find MODULE_LICENSE("GPL"), MODULE_AUTHOR() etc.
# thanks to "merseyviking" from stack overflow
add_definitions(-D__KERNEL__ -DMODULE)
add_executable(proxy-exec proxy-exec.c)
target_include_directories("proxy-exec" PRIVATE ${KERNELHEADERS_INCLUDE_DIRS})