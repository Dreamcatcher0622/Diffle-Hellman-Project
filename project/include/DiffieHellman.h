#ifndef DIFFIE_H
#define DIFFIE_H

#include "utils.h"

struct DiffieHellman
{
    long long p;          // 大素数
    long long g;          // 生成元
    long long privateKey; // 私钥
    long long publicKey;  // 公钥

    DiffieHellman(long long prime, long long generator) : p(prime), g(generator)
    {
        privateKey = rand() % (p - 2) + 1; // 随机生成私钥
        publicKey = modExp(g, privateKey, p);
    }

    // 快速幂取模算法
    long long modExp(long long base, long long exp, long long mod)
    {
        long long result = 1;
        while (exp > 0)
        {
            if (exp % 2 == 1)
                result = (result * base) % mod;
            base = (base * base) % mod;
            exp /= 2;
        }
        return result;
    }

    // 计算共享密钥
    long long computeSharedKey(long long receivedPublicKey)
    {
        return modExp(receivedPublicKey, privateKey, p);
    }
};

void updateKey(int socket, DiffieHellman &dh, std::vector<unsigned char> &key)
{
    // 重新生成 DH 密钥对
    DiffieHellman newDh(dh.p, dh.g);

    // 发送并接收新的公钥
    long long newPublicKey = newDh.publicKey;
    send(socket, (char *)&newPublicKey, sizeof(newPublicKey), 0);

    long long receivedPublicKey;
    recv(socket, (char *)&receivedPublicKey, sizeof(receivedPublicKey), 0);

    // 计算新的共享密钥
    long long newSharedKey = newDh.computeSharedKey(receivedPublicKey);
    key.assign(32, newSharedKey % 256); // 重新设置为256位

    // 输出并更新原始 Diffie-Hellman 对象
    dh = newDh;

    std::cout << "New shared key established.\n";
}

#endif DIFFIE_H