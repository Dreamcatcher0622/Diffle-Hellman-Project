#include "./include/DiffieHellman.h"
#include "./include/AES256GCM.h"

const char *SERVER_IP = "127.0.0.1";
const int PORT = 8081;

void runClient()
{
    int sock = 0;
    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        handleError("socket creation failed");

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0)
        handleError("invalid address");

    std::cout << "Connecting to server: " << SERVER_IP << ':' << PORT << std::endl;

    while (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
    {
        std::cerr << "Connection failed, retrying..." << std::endl;
        sleep(3); // 等待3秒再重试
    }
    std::cout << "Connected to server!" << std::endl;

    long long p = 23;
    long long g = 5;
    DiffieHellman dh(p, g);

    long long serverPublicKey;
    recv(sock, (char *)&serverPublicKey, sizeof(serverPublicKey), 0);

    long long clientPublicKey = dh.publicKey;
    send(sock, (char *)&clientPublicKey, sizeof(clientPublicKey), 0);

    long long sharedKey = dh.computeSharedKey(serverPublicKey);
    std::vector<unsigned char> key(32, sharedKey % 256);
    std::vector<unsigned char> iv(12, 0x01);

    std::cout << "Secure channel established. Type 'exit' to quit.\n";

    int messageCounter = 0;
    const int maxMessagesBeforeKeyUpdate = 5;

    while (true)
    {
        std::cout << "You: ";
        std::string message;
        std::getline(std::cin, message);

        std::vector<unsigned char> plaintext(message.begin(), message.end());
        std::vector<unsigned char> encryptedMessage = AES256GCM::encrypt(plaintext, key, iv);
        send(sock, (char *)encryptedMessage.data(), encryptedMessage.size(), 0);

        if (message == "exit")
            break;

        std::vector<unsigned char> encryptedReply(1024);
        int replySize = recv(sock, (char *)encryptedReply.data(), encryptedReply.size(), 0);
        if (replySize <= 0)
            break;
        encryptedReply.resize(replySize);

        std::vector<unsigned char> replyData = AES256GCM::decrypt(encryptedReply, key, iv);
        std::string reply(replyData.begin(), replyData.end());

        std::cout << "Server: " << reply << std::endl;

        if (reply == "exit")
            break;

        // 增加计数并检查是否需要更新密钥
        if (++messageCounter >= maxMessagesBeforeKeyUpdate)
        {
            updateKey(sock, dh, key);
            messageCounter = 0;
        }
    }

    close(sock);
}

int main()
{
    runClient();
    return 0;
}