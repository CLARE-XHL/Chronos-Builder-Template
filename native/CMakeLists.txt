cmake_minimum_required(VERSION 3.15)
project(decryptor)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Node.js 头文件
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/node_modules/node-api-headers/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/node_modules/node-addon-api)

# OpenSSL 路径由 CMake 命令行传入（-DOPENSSL_*）
# 这里不再硬编码，直接使用变量
include_directories(${OPENSSL_INCLUDE_DIR})

add_library(decryptor SHARED src/decryptor.cc)

set_target_properties(decryptor PROPERTIES
    PREFIX ""
    SUFFIX ".node"
    CXX_STANDARD 17
)

target_link_libraries(decryptor
    ${OPENSSL_SSL_LIBRARY}
    ${OPENSSL_CRYPTO_LIBRARY}
)

target_compile_definitions(decryptor PRIVATE
    NAPI_DISABLE_CPP_EXCEPTIONS
)

target_include_directories(decryptor PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/node_modules/node-addon-api
    ${CMAKE_CURRENT_SOURCE_DIR}/node_modules/node-api-headers/include
    ${OPENSSL_INCLUDE_DIR}
)
