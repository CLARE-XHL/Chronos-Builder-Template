cmake_minimum_required(VERSION 3.15)
project(decryptor)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 使用 CMake 命令行传入的变量
# 如果变量未定义，提供后备路径
if (NOT NODE_ADDON_API_INCLUDE)
    set(NODE_ADDON_API_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/node_modules/node-addon-api")
endif()

if (NOT NODE_HEADERS_INCLUDE)
    # 尝试从 node-gyp 缓存中查找
    # 这是一个后备方案，最好还是从命令行传入
    set(NODE_HEADERS_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/../node-headers/include/node")
endif()

# 添加包含目录
include_directories(${NODE_ADDON_API_INCLUDE})
include_directories(${NODE_HEADERS_INCLUDE})

# OpenSSL 路径由命令行传入
# ...

add_library(decryptor SHARED src/decryptor.cc)

# ... 其余部分保持不变
