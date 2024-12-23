#ifndef AES_H
#define AES_H

#include "utils.h"

class AES256GCM {
public:
    static std::vector<unsigned char> encrypt(const std::vector<unsigned char> &plaintext, 
                                              const std::vector<unsigned char> &key, 
                                              const std::vector<unsigned char> &iv) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create cipher context");

        std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> tag(16);

        int len;
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) != 1)
            throw std::runtime_error("EncryptInit failed");

        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1)
            throw std::runtime_error("EncryptUpdate failed");

        int ciphertext_len = len;
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
            throw std::runtime_error("EncryptFinal failed");

        ciphertext_len += len;
        ciphertext.resize(ciphertext_len);

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1)
            throw std::runtime_error("Failed to get tag");

        ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
        EVP_CIPHER_CTX_free(ctx);

        return ciphertext;
    }

    static std::vector<unsigned char> decrypt(const std::vector<unsigned char> &ciphertext, 
                                              const std::vector<unsigned char> &key, 
                                              const std::vector<unsigned char> &iv) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create cipher context");

        std::vector<unsigned char> plaintext(ciphertext.size() - 16);
        int len;

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) != 1)
            throw std::runtime_error("DecryptInit failed");

        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size() - 16) != 1)
            throw std::runtime_error("DecryptUpdate failed");

        int plaintext_len = len;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, 
            const_cast<unsigned char*>(ciphertext.data() + ciphertext.size() - 16)) != 1)
            throw std::runtime_error("Set tag failed");

        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1)
            throw std::runtime_error("DecryptFinal failed");

        plaintext_len += len;
        plaintext.resize(plaintext_len);
        EVP_CIPHER_CTX_free(ctx);

        return plaintext;
    }
};

#endif AES_H