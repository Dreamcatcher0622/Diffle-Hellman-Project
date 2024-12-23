#include "../include/DiffieHellman.h"
#include "../include/AES256GCM.h"

const int PORT = 8082;

void runServer()
{
    // 初始化 SSL
    initializeSSL();
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
        handleError("Unable to create SSL context");

    // 加载证书和私钥
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0)
        handleError("Failed to load server certificate");

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0)
        handleError("Failed to load server private key");

    int server_fd, client_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
        handleError("socket failed");

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
        handleError("bind failed");

    if (listen(server_fd, 1) < 0)
        handleError("listen failed");

    std::cout << "Server listening on port " << PORT << "..." << std::endl;

    if ((client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
        handleError("accept failed");

    // 使用 SSL
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);
    if (SSL_accept(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        handleError("SSL handshake failed");
    }
    std::cout << "SSL handshake successful!" << std::endl;

    // 后续的通信逻辑用 SSL 替代普通 socket
    // 替换 send 和 recv 为 SSL_write 和 SSL_read
    long long p = 23; // 简化的素数
    long long g = 5;  // 简化的生成元
    DiffieHellman dh(p, g);

    long long serverPublicKey = dh.publicKey;
    SSL_write(ssl, &serverPublicKey, sizeof(serverPublicKey));

    long long clientPublicKey;
    SSL_read(ssl, &clientPublicKey, sizeof(clientPublicKey));

    long long sharedKey = dh.computeSharedKey(clientPublicKey);
    std::vector<unsigned char> key(32, sharedKey % 256); // 将共享密钥扩展为 256 位
    std::vector<unsigned char> iv(12, 0x01);             // 示例 IV

    // 后续逻辑与原先相同，只需将 socket 替换为 SSL
    std::cout << "Secure channel established. Type 'exit' to quit.\n";

    int messageCounter = 0;
    const int maxMessagesBeforeKeyUpdate = 5;

    while (true)
    {
        std::vector<unsigned char> encryptedMessage(1024);
        int messageSize = SSL_read(ssl, encryptedMessage.data(), encryptedMessage.size());
        if (messageSize <= 0)
            break;
        encryptedMessage.resize(messageSize);

        std::vector<unsigned char> plaintext = AES256GCM::decrypt(encryptedMessage, key, iv);
        std::string receivedMessage(plaintext.begin(), plaintext.end());

        std::cout << "Client: " << receivedMessage << std::endl;

        if (receivedMessage == "exit")
            break;

        std::cout << "You: ";
        std::string reply;
        std::getline(std::cin, reply);

        std::vector<unsigned char> replyData(reply.begin(), reply.end());
        std::vector<unsigned char> encryptedReply = AES256GCM::encrypt(replyData, key, iv);
        SSL_write(ssl, encryptedReply.data(), encryptedReply.size());

        if (reply == "exit")
            break;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
    close(server_fd);

    SSL_CTX_free(ctx);
    cleanupSSL();
}

int main()
{
    runServer();
    return 0;
}