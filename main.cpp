#include <iostream>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <fstream>
#include <string>
#include <array>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <thread>
#include <iomanip>

#include "magma.h"
#include "cbc.h"
#include "file_utils.h"
#include "mysha.h"
#include "KDF.h"

const int PORT = 3333;

static std::vector<uint8_t> ivToBytes(uint64_t iv) {
    std::vector<uint8_t> v(8);
    for (int i = 0; i < 8; ++i) {
        v[i] = static_cast<uint8_t>((iv >> (8 * (7 - i))) & 0xFF);
    }
    return v;
}

static uint64_t bytesToIv(const std::vector<uint8_t>& v) {
    if (v.size() < 8) throw std::runtime_error("bytesToIv: need at least 8 bytes");
    uint64_t iv = 0;
    for (int i = 0; i < 8; ++i) iv = (iv << 8) | static_cast<uint64_t>(v[i]);
    return iv;
}

std::array<uint32_t,8> readKeys(const std::string& filename) {
    std::ifstream fin(filename, std::ios::binary);
    if(!fin) throw std::runtime_error("Не удалось открыть файл ключей: " + filename);
    std::array<uint32_t,8> keys{};
     fin.read(reinterpret_cast<char*>(keys.data()), keys.size() * sizeof(uint32_t));

    if (fin.gcount() != keys.size() * sizeof(uint32_t))
        throw std::runtime_error("Файл ключей имеет неверный размер");

    return keys;
}

void printUsage(const char* programName){
    std::cout << "Использование:\n";
    std::cout << "  " << programName << " --server\n";
    std::cout << "  " << programName << " --client <ip_сервера>\n";
    std::cout << "  " << programName << " -e <входной_файл> <ключевой_файл> [выходной_файл]\n";
    std::cout << "  " << programName << " -d <входной_файл> <ключевой_файл> [выходной_файл]\n\n";

    std::cout << "Режимы:\n";
    std::cout << "  --server                 запустить сервер\n";
    std::cout << "  --client <ip>            подключиться к серверу\n";
    std::cout << "  -e                       локальное шифрование файла\n";
    std::cout << "  -d                       локальное расшифрование файла\n\n";

    std::cout << "Примеры:\n";
    std::cout << "  " << programName << " --server\n";
    std::cout << "  " << programName << " --client 127.0.0.1\n";
    std::cout << "  " << programName << " -e input.txt keys.bin output.dat\n";
    std::cout << "  " << programName << " -d output.dat keys.bin decrypted.txt\n";
}

std::string generateOutputFilename(const std::string& inputFile, bool isEncryption){
    size_t lastDot = inputFile.find_last_of('.');
    std::string baseName = (lastDot!=std::string::npos)? inputFile.substr(0,lastDot) : inputFile;
    return baseName + (isEncryption?".encrypted":".decrypted");
}

std::vector<uint8_t> receiveRaw(int sock, size_t len){
    std::vector<uint8_t> data(len);
    size_t total = 0;
    while(total < len){
        ssize_t n = recv(sock, reinterpret_cast<char*>(data.data()) + total, len - total, 0);
        if(n <= 0) return {};
        total += static_cast<size_t>(n);
    }
    return data;
}

bool sendRaw(int sock,const std::vector<uint8_t>& data){
    size_t total = 0;
    while(total < data.size()){
        ssize_t n = send(sock, reinterpret_cast<const char*>(data.data()) + total, data.size() - total, 0);
        if(n <= 0) return false;
        total += static_cast<size_t>(n);
    }
    return true;
}

uint64_t iv16_to_cbc64(const std::array<uint8_t,16>& iv16) {
    uint64_t iv64 = 0;
    for(int i = 0; i < 8; i++) {
        iv64 = (iv64 << 8) | iv16[i];
    }
    return iv64;
}

// Сервер
void run_server(){
    std::array<uint32_t,8> MasterKey = readKeys("keys.bin");
    std::array<uint8_t,16> iv16 = genSeed16();
    std::array<uint8_t,32> sessionKeyBytes = KDF(MasterKey, iv16);
    std::vector<uint8_t> plaintext = readFile("message.txt");
    std::array<uint32_t,8> sessionKey{};
    for(int i = 0; i < 8; i++) {
        sessionKey[i] =
            (uint32_t(sessionKeyBytes[i*4+0]) << 24) |
            (uint32_t(sessionKeyBytes[i*4+1]) << 16) |
            (uint32_t(sessionKeyBytes[i*4+2]) << 8 ) |
             uint32_t(sessionKeyBytes[i*4+3]);
        }
    uint64_t iv64 = iv16_to_cbc64(iv16);
    int server_fd = socket(AF_INET, SOCK_STREAM,0);
    if(server_fd<0){ perror("socket"); exit(1); }
    int reuse=1; setsockopt(server_fd,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));

    sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_port=htons(PORT); addr.sin_addr.s_addr=INADDR_ANY;
    if(bind(server_fd,(sockaddr*)&addr,sizeof(addr))<0){ perror("bind"); close(server_fd); exit(1);}
    if(listen(server_fd,5)<0){ perror("listen"); close(server_fd); exit(1);}
    std::cout << "Server listening on port " << PORT << "\n";

    while(true){
        int client_fd = accept(server_fd,nullptr,nullptr);
        if(client_fd < 0) { perror("accept"); continue; }

        std::thread([client_fd, plaintext, sessionKey, iv16, iv64](){
            std::cout << "Client connected.\n";
            
            if(receiveRaw(client_fd,5)!=std::vector<uint8_t>{'H','E','L','L','O'}){ close(client_fd); return;}
            if(!sendRaw(client_fd,{'A','C','K','_','H','E','L','L','O'})){ close(client_fd); return;}
            if(receiveRaw(client_fd,5)!=std::vector<uint8_t>{'R','E','A','D','Y'}){ close(client_fd); return;}
            if(!sendRaw(client_fd,{'G','O'})){ close(client_fd); return;}

            std::vector<uint64_t> blocks = splitBlocksForEncrypt(plaintext);

            std::vector<uint64_t> encryptedBlocks = encryptCBC(blocks, iv64, sessionKey);
            std::vector<uint8_t> encryptedData = joinBlocksForEncrypt(encryptedBlocks);

            std::vector<uint8_t> ivBytes(iv16.begin(), iv16.end());
            std::vector<uint8_t> finalData;
            finalData.reserve(ivBytes.size() + encryptedData.size());
            finalData.insert(finalData.end(), ivBytes.begin(), ivBytes.end());
            finalData.insert(finalData.end(), encryptedData.begin(), encryptedData.end());

            uint32_t netLen = htonl(static_cast<uint32_t>(finalData.size()));
            uint8_t lenBuf[4];
            std::memcpy(lenBuf, &netLen, 4);
            if(!sendRaw(client_fd, std::vector<uint8_t>(lenBuf, lenBuf + 4))){ close(client_fd); return; }
            if(!sendRaw(client_fd, finalData)){ close(client_fd); return; }

            std::cout << "Sent packet (" << finalData.size() << " bytes), IV: ";
            for (auto b : ivBytes) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
            std::cout << std::dec << "\n";
        }).detach();
    }
    close(server_fd);
}

// Клиент 
    void run_client(const std::string& server_ip, const std::array<uint32_t,8>& keyArray){
    int sock = socket(AF_INET, SOCK_STREAM,0);
    if(sock<0){ perror("socket"); exit(1);}
    sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_port=htons(PORT);
    if(inet_pton(AF_INET,server_ip.c_str(),&addr.sin_addr)<=0){ std::cerr << "Invalid IP\n"; close(sock); exit(1); }
    if(connect(sock,(sockaddr*)&addr,sizeof(addr))<0){ perror("connect"); close(sock); exit(1); }

    std::cout << "Connected. Handshake...\n";
    sendRaw(sock,{'H','E','L','L','O'});
    if(receiveRaw(sock,9)!=std::vector<uint8_t>{'A','C','K','_','H','E','L','L','O'}){ std::cerr<<"Handshake failed\n"; close(sock); return; }
    sendRaw(sock,{'R','E','A','D','Y'});
    if(receiveRaw(sock,2)!=std::vector<uint8_t>{'G','O'}){ std::cerr<<"Handshake failed\n"; close(sock); return; }
    std::cout << "Handshake OK.\n";

    std::vector<uint8_t> lenBuf = receiveRaw(sock, 4);
    if(lenBuf.size() != 4){ std::cerr << "No data\n"; close(sock); return; }
    uint32_t netLen = 0;
    std::memcpy(&netLen, lenBuf.data(), 4);
    uint32_t packetLen = ntohl(netLen);

    std::vector<uint8_t> packet = receiveRaw(sock, packetLen);
    if(packet.size() != packetLen){ std::cerr << "Incomplete packet\n"; close(sock); return; }
    if(packet.size() < 16){ std::cerr << "Invalid packet\n"; close(sock); return; }

    std::vector<uint8_t> ivBytes(packet.begin(), packet.begin() + 16);
    std::vector<uint8_t> ciphertext(packet.begin() + 16, packet.end());

    std::array<uint8_t,16> iv16{};
    std::copy(ivBytes.begin(), ivBytes.end(), iv16.begin());

    std::array<uint32_t,8> masterKey = keyArray;


    std::array<uint8_t,32> sessionKeyBytes = KDF(masterKey, iv16);

    std::array<uint32_t,8> sessionKey{};
    for(int i = 0; i < 8; i++){
        sessionKey[i] =
            (uint32_t(sessionKeyBytes[i*4+0]) << 24) |
            (uint32_t(sessionKeyBytes[i*4+1]) << 16) |
            (uint32_t(sessionKeyBytes[i*4+2]) << 8 ) |
             uint32_t(sessionKeyBytes[i*4+3]);
    }

    uint64_t iv64 = iv16_to_cbc64(iv16);

    std::vector<uint64_t> encryptedBlocks = splitBlocksForDecrypt(ciphertext);

    std::vector<uint64_t> decryptedBlocks = decryptCBC(encryptedBlocks, iv64, sessionKey);

    std::vector<uint8_t> plaintext = joinBlocksForDecrypt(decryptedBlocks);

    std::cout << "Decrypted message:\n"
              << std::string(plaintext.begin(), plaintext.end()) << "\n";

    close(sock);
}

int main(int argc,char* argv[]){
    if(argc>=2 && std::string(argv[1])=="--server"){ run_server(); return 0;}
    if(argc>=3 && std::string(argv[1])=="--client"){ run_client(argv[2], readKeys("keys.bin")); return 0;}

    if(argc<4){ printUsage(argv[0]); return 1; }
    std::string mode=argv[1], inputfile=argv[2], keyfile=argv[3];
    std::string outputfile=(argc>4)? argv[4] : generateOutputFilename(inputfile,mode=="-e");
    bool isEncryption = (mode=="-e");

    std::array<uint32_t,8> keyArray = readKeys(keyfile);
    std::vector<uint8_t> inputData = readFile(inputfile);
if(isEncryption){
    std::vector<uint64_t> blocks = splitBlocksForEncrypt(inputData);
    std::array<uint8_t,16> iv16 = genSeed16();
    uint64_t iv = iv16_to_cbc64(iv16);
    std::vector<uint64_t> encryptedBlocks = encryptCBC(blocks, iv, keyArray);
    std::vector<uint8_t> encryptedData = joinBlocksForEncrypt(encryptedBlocks);

    std::vector<uint8_t> ivBytes = ivToBytes(iv);
    std::vector<uint8_t> finalData;
    finalData.reserve(ivBytes.size() + encryptedData.size());
    finalData.insert(finalData.end(), ivBytes.begin(), ivBytes.end());
    finalData.insert(finalData.end(), encryptedData.begin(), encryptedData.end());

    writeFile(outputfile, finalData);
    std::cout << "Encrypted "<< inputfile <<" -> "<< outputfile << "\n";
} else {
    if(inputData.size() < 8){ std::cerr << "Invalid input file\n"; return 1; }
    std::vector<uint8_t> ivBytes(inputData.begin(), inputData.begin() + 8);
    uint64_t iv = bytesToIv(ivBytes);
    std::vector<uint8_t> encData(inputData.begin() + 8, inputData.end());

    std::vector<uint64_t> encryptedBlocks = splitBlocksForDecrypt(encData);
    std::vector<uint64_t> decryptedBlocks = decryptCBC(encryptedBlocks, iv, keyArray);
    std::vector<uint8_t> decryptedData = joinBlocksForDecrypt(decryptedBlocks);
    writeFile(outputfile, decryptedData);
    std::cout << "Decrypted "<< inputfile <<" -> "<< outputfile << "\n";
}

    return 0;
}
