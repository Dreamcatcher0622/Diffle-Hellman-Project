#ifndef UTILS_H
#define UTILS_H

#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <cmath>
#include <cerrno>
#include <cstring>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <future>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// 工具函数
void handleError(const std::string &msg)
{
    std::cerr << msg << ": " << strerror(errno) << std::endl;
    exit(EXIT_FAILURE);
}

// 新增 SSL 初始化代码
void initializeSSL()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// 新增 SSL 清理代码
void cleanupSSL()
{
    EVP_cleanup();
}

// 转换二进制到十六进制
std::string toHex(const std::vector<unsigned char> &data)
{
    std::string hex;
    for (unsigned char byte : data)
    {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", byte);
        hex += buf;
    }
    return hex;
}

#endif