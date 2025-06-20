#!/bin/bash

# 设置构建目录
BUILD_DIR="build"

# 清理函数
clean() {
    if [ -d "$BUILD_DIR" ]; then
        echo "Del $BUILD_DIR..."
        rm -rf "$BUILD_DIR"
    fi
}

build() {
    if [ -d "$BUILD_DIR" ]; then
        clean
    fi
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR" || exit
    cmake ..
    make
}

main() {
    if [ "$1" = "clean" ]; then
        clean
        exit 0
    fi
    build
    echo
    echo "Build completed successfully."
    echo "Runing..."
    echo
    ./test/cipher_test
}

main "$@"