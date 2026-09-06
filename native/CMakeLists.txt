cmake_minimum_required(VERSION 3.15)
project(decryptor)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(node_modules/node-addon-api)

add_library(decryptor SHARED
    src/decryptor.cc
)

set_target_properties(decryptor PROPERTIES
    PREFIX ""
    SUFFIX ".node"
    CXX_STANDARD 17
)

find_package(OpenSSL REQUIRED)
target_link_libraries(decryptor
    node-addon-api
    OpenSSL::SSL
    OpenSSL::Crypto
)

target_compile_definitions(decryptor PRIVATE
    NAPI_DISABLE_CPP_EXCEPTIONS
)

target_include_directories(decryptor PRIVATE
    node_modules/node-addon-api
    ${OPENSSL_INCLUDE_DIR}
)
