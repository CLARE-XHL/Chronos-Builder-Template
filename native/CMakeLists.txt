cmake_minimum_required(VERSION 3.15)
project(decryptor)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 直接添加头文件路径（node-addon-api 没有 CMakeLists.txt）
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/node_modules/node-addon-api)

# 设置 OpenSSL 路径（关键！）
set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")
set(OPENSSL_CRYPTO_LIBRARY "C:/Program Files/OpenSSL-Win64/lib/libcrypto.lib")
set(OPENSSL_SSL_LIBRARY "C:/Program Files/OpenSSL-Win64/lib/libssl.lib")
set(OPENSSL_INCLUDE_DIR "C:/Program Files/OpenSSL-Win64/include")

find_package(OpenSSL REQUIRED)

add_library(decryptor SHARED src/decryptor.cc)

set_target_properties(decryptor PROPERTIES
    PREFIX ""
    SUFFIX ".node"
    CXX_STANDARD 17
)

target_link_libraries(decryptor
    OpenSSL::SSL
    OpenSSL::Crypto
)

target_compile_definitions(decryptor PRIVATE
    NAPI_DISABLE_CPP_EXCEPTIONS
)

target_include_directories(decryptor PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/node_modules/node-addon-api
    ${OPENSSL_INCLUDE_DIR}
)
