#include "../include/DiffieHellman.h"
#include "../include/AES256GCM.h"

const char *SERVER_IP = "127.0.0.1";
const int PORT = 8081;

void runClient()
{
    // 初始化 SSL
    initializeSSL();
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
        handleError("Unable to create SSL context");

    // 加载 CA 证书
    if (SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL) <= 0)
        handleError("Failed to load CA certificate");

    int sock = 0;
    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        handleError("socket creation failed");

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0)
        handleError("invalid address");

    std::cout << "Connecting to server: " << SERVER_IP << ':' << PORT << std::endl;

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        handleError("Connection failed");

    // 使用 SSL
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0)
    {
        // ERR_print_errors_fp(stderr);
        std::cerr << "Certificate verification failed. Possible MITM attack!" << std::endl;
        handleError("SSL handshake failed");
    }

    std::cout << "Server certificate verified successfully." << std::endl;

    // 后续的通信逻辑用 SSL 替代普通 socket
    long long p = 23;
    long long g = 5;
    DiffieHellman dh(p, g);

    long long serverPublicKey;
    SSL_read(ssl, &serverPublicKey, sizeof(serverPublicKey));

    long long clientPublicKey = dh.publicKey;
    SSL_write(ssl, &clientPublicKey, sizeof(clientPublicKey));

    long long sharedKey = dh.computeSharedKey(serverPublicKey);
    std::vector<unsigned char> key(32, sharedKey % 256);
    std::vector<unsigned char> iv(12, 0x01);

    // 后续逻辑与原先相同，只需将 socket 替换为 SSL
    std::cout << "Secure channel established. Type 'exit' to quit.\n";

    while (true)
    {
        std::cout << "You: ";
        std::string message;
        std::getline(std::cin, message);

        std::vector<unsigned char> plaintext(message.begin(), message.end());
        std::vector<unsigned char> encryptedMessage = AES256GCM::encrypt(plaintext, key, iv);
        SSL_write(ssl, encryptedMessage.data(), encryptedMessage.size());

        if (message == "exit")
            break;

        std::vector<unsigned char> encryptedReply(1024);
        int replySize = SSL_read(ssl, encryptedReply.data(), encryptedReply.size());
        if (replySize <= 0)
            break;
        encryptedReply.resize(replySize);

        std::vector<unsigned char> replyData = AES256GCM::decrypt(encryptedReply, key, iv);
        std::string reply(replyData.begin(), replyData.end());

        std::cout << "Server: " << reply << std::endl;

        if (reply == "exit")
            break;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);

    SSL_CTX_free(ctx);
    cleanupSSL();
}

int main()
{
    runClient();
    return 0;
}