#ifndef KDF_H
#define KDF_H

#include <array>
#include <vector>
#include <cstdint>


// 8 × uint32 → 32 байта (big-endian)
std::array<uint8_t,32> keyArrayToBytes(const std::array<uint32_t,8>& k);

// 32 байта → 8 × uint32 (big-endian)
std::array<uint32_t,8> BytesKeyToArray(const std::array<uint8_t,32>& k);

// 16-байтный seed
std::array<uint8_t,16> genSeed16();

// HMAC-SHA256
std::array<uint8_t,32> HMAC(const std::array<uint8_t,32>& Kin,
                            const std::vector<uint8_t>& T);

// KDF (ГОСТ Р 50.1.113 стиль)
std::array<uint8_t, 32> KDF(std::array<uint32_t,8>& key, std::array<uint8_t,16>& seed);

#endif
