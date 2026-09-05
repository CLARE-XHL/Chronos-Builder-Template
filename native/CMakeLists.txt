cmake_minimum_required(VERSION 3.15)
project(decryptor)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 添加 node-addon-api 子目录
add_subdirectory(node_modules/node-addon-api)

# 创建 Node.js 原生模块
add_library(decryptor SHARED
    src/decryptor.cc
)

# 设置目标属性
set_target_properties(decryptor PROPERTIES
    PREFIX ""
    SUFFIX ".node"
    CXX_STANDARD 17
)

# 链接 OpenSSL
find_package(OpenSSL REQUIRED)
target_link_libraries(decryptor
    node-addon-api
    OpenSSL::SSL
    OpenSSL::Crypto
)

# 定义预处理器宏
target_compile_definitions(decryptor PRIVATE
    NAPI_DISABLE_CPP_EXCEPTIONS
)

# 包含目录
target_include_directories(decryptor PRIVATE
    node_modules/node-addon-api
    ${OPENSSL_INCLUDE_DIR}
)
