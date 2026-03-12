#include <vector>
#include <cstdint>
#include <array>
uint64_t generateIV(); //генерация вектора инициализации


std::vector<uint64_t> encryptCBC(const std::vector<uint64_t>& blocks, uint64_t IV, const std::array<uint32_t,8>& keys);//Шифрование блоков с помощью CBC
std::vector<uint64_t> decryptCBC(const std::vector<uint64_t>& cblocks, uint64_t IV, const std::array<uint32_t,8>& keys);//Расшифрование блоков с помощью CBC