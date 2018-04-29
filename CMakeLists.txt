cmake_minimum_required(VERSION 3.7)
project(secret)

#I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib
set( OPENSSL_ROOT_DIR "/usr/local/opt/openssl")
find_package(OpenSSL REQUIRED)
if ( OPENSSL_FOUND )
    message(STATUS "OpenSSL Found: ${OPENSSL_VERSION}")
    message(STATUS "OpenSSL Include: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL Libraries: ${OPENSSL_LIBRARIES}")
endif()

include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${CMAKE_CURRENT_LIST_DIR})

set(CMAKE_C_STANDARD 99)
set(SOURCE_FILES main.c)

add_executable(secret ${SOURCE_FILES})
target_link_libraries(secret SSL crypto)