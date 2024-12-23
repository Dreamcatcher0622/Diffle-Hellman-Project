#include "./include/DiffieHellman.h"
#include "./include/AES256GCM.h"

const int PORT = 8082;

void runServer()
{
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

    long long p = 23; // 简化的素数
    long long g = 5;  // 简化的生成元
    DiffieHellman dh(p, g);

    long long serverPublicKey = dh.publicKey;
    send(client_fd, (char *)&serverPublicKey, sizeof(serverPublicKey), 0);

    long long clientPublicKey;
    recv(client_fd, (char *)&clientPublicKey, sizeof(clientPublicKey), 0);

    long long sharedKey = dh.computeSharedKey(clientPublicKey);
    std::vector<unsigned char> key(32, sharedKey % 256); // 将共享密钥扩展为 256 位
    std::vector<unsigned char> iv(12, 0x01);             // 示例 IV

    std::cout << "Secure channel established. Type 'exit' to quit.\n";

    int messageCounter = 0;
    const int maxMessagesBeforeKeyUpdate = 5;

    while (true)
    {
        std::vector<unsigned char> encryptedMessage(1024);
        int messageSize = recv(client_fd, (char *)encryptedMessage.data(), encryptedMessage.size(), 0);
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
        send(client_fd, (char *)encryptedReply.data(), encryptedReply.size(), 0);

        if (reply == "exit")
            break;

        // 增加计数并检查是否需要更新密钥
        if (++messageCounter >= maxMessagesBeforeKeyUpdate)
        {
            updateKey(client_fd, dh, key);
            messageCounter = 0;
        }
    }

    close(client_fd);
    close(server_fd);
}

int main()
{
    runServer();
    return 0;
}