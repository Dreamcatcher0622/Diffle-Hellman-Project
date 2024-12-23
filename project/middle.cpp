#include "./include/DiffieHellman.h"
#include "./include/AES256GCM.h"

const int LISTEN_PORT = 8081; // 中间人监听客户端的端口
const char *SERVER_IP = "127.0.0.1";
const int SERVER_PORT = 8082; // 中间人连接服务器的端口

std::vector<unsigned char> ListenTOClient(int &listen_fd, int &client_fd, DiffieHellman &dhClient)
{
    struct sockaddr_in listen_addr, client_addr;
    int addrlen = sizeof(client_addr);

    // 创建监听套接字
    if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
        handleError("socket creation failed");

    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(LISTEN_PORT);

    if (bind(listen_fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0)
        handleError("bind failed");

    if (listen(listen_fd, 1) < 0)
        handleError("listen failed");

    std::cout << "MITM listening on port " << LISTEN_PORT << "..." << std::endl;

    if ((client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, (socklen_t *)&addrlen)) < 0)
        handleError("accept failed");

    std::cout << "MITM connected to Client." << std::endl;

    // 向客户端发送伪造公钥
    long long mitmPublicKeyToClient = dhClient.publicKey;
    send(client_fd, (char *)&mitmPublicKeyToClient, sizeof(mitmPublicKeyToClient), 0);

    // 接收客户端公钥
    long long clientPublicKey;
    recv(client_fd, (char *)&clientPublicKey, sizeof(clientPublicKey), 0);

    // 计算共享密钥
    long long sharedKeyWithClient = dhClient.computeSharedKey(clientPublicKey);
    std::vector<unsigned char> keyClient(32, sharedKeyWithClient % 256);

    return keyClient;
}

std::vector<unsigned char> ConnectToServer(int &server_fd, DiffieHellman &dhServer)
{
    struct sockaddr_in server_addr;

    // 连接真实服务器
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        handleError("socket creation failed");

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    while (connect(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        std::cerr << "Connection failed, retrying..." << std::endl;
        sleep(3); // 等待3秒再重试
    }
    std::cout << "MITM connected to Server\n";

    // 接收服务器公钥
    long long serverPublicKey;
    recv(server_fd, (char *)&serverPublicKey, sizeof(serverPublicKey), 0);

    // 向服务器发送伪造公钥
    long long mitmPublicKeyToServer = dhServer.publicKey;
    send(server_fd, (char *)&mitmPublicKeyToServer, sizeof(mitmPublicKeyToServer), 0);

    // 计算共享密钥
    long long sharedKeyWithServer = dhServer.computeSharedKey(serverPublicKey);

    std::vector<unsigned char> keyServer(32, sharedKeyWithServer % 256);

    return keyServer;
}

void runMITM()
{
    // 中间人的Diffie-Hellman密钥对
    long long p = 23; // 简化的素数
    long long g = 5;  // 简化的生成元

    int listen_fd, client_fd, server_fd;
    DiffieHellman dhClient(p, g), dhServer(p, g);

    std::future<std::vector<unsigned char>> resultlKeyClient = std::async(std::launch::async, ListenTOClient, std::ref(listen_fd), std::ref(client_fd), std::ref(dhClient));
    std::future<std::vector<unsigned char>> resultlKeyServer = std::async(std::launch::async, ConnectToServer, std::ref(server_fd), std::ref(dhServer));

    std::vector<unsigned char> keyClient = resultlKeyClient.get();
    std::vector<unsigned char> keyServer = resultlKeyServer.get();
    std::cout << "MITM attack established. Relaying messages.\n";

    std::vector<unsigned char> iv(12, 0x01); // 示例 IV
                                             // ---------------------------------------------------

    char buffer[1024];
    while (true)
    {
        // 接收客户端消息
        int bytesReceived = recv(client_fd, buffer, sizeof(buffer), 0);
        if (bytesReceived <= 0)
            break;

        std::vector<unsigned char> encryptedMessage(buffer, buffer + bytesReceived);
        std::vector<unsigned char> plaintext = AES256GCM::decrypt(encryptedMessage, keyClient, iv);
        std::cout << "Client: " << std::string(plaintext.begin(), plaintext.end()) << std::endl;

        // 转发到服务器
        std::vector<unsigned char> reEncryptedMessage = AES256GCM::encrypt(plaintext, keyServer, iv);
        send(server_fd, (char *)reEncryptedMessage.data(), reEncryptedMessage.size(), 0);

        // 接收服务器消息
        bytesReceived = recv(server_fd, buffer, sizeof(buffer), 0);
        if (bytesReceived <= 0)
            break;

        encryptedMessage.assign(buffer, buffer + bytesReceived);
        plaintext = AES256GCM::decrypt(encryptedMessage, keyServer, iv);
        std::cout << "Server: " << std::string(plaintext.begin(), plaintext.end()) << std::endl;

        // 转发到客户端
        reEncryptedMessage = AES256GCM::encrypt(plaintext, keyClient, iv);
        send(client_fd, (char *)reEncryptedMessage.data(), reEncryptedMessage.size(), 0);
    }

    close(client_fd);
    close(server_fd);
    close(listen_fd);
}

int main()
{
    runMITM();
    return 0;
}