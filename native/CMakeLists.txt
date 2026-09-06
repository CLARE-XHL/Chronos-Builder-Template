cmake_minimum_required(VERSION 3.15)
project(decryptor)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 使用 CMake 命令行传入的变量（由 build.yml 设置）
# 如果变量未定义，使用默认后备路径
if (NOT NODE_ADDON_API_INCLUDE)
    set(NODE_ADDON_API_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/node_modules/node-addon-api")
endif()

if (NOT NODE_HEADERS_INCLUDE)
    set(NODE_HEADERS_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/../node-headers/include/node")
endif()

# 添加包含目录
include_directories(${NODE_ADDON_API_INCLUDE})
include_directories(${NODE_HEADERS_INCLUDE})

# OpenSSL 路径由命令行传入
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
    ${NODE_ADDON_API_INCLUDE}
    ${NODE_HEADERS_INCLUDE}
    ${OPENSSL_INCLUDE_DIR}
)
