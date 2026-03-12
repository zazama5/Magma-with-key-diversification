#include <iostream>
#include <vector>
#include <array>
#include <cstdint>
#include <algorithm>
#include <random>
#include "KDF.h"
#include "mysha.h"


std::array<uint8_t,32> keyArrayToBytes(const std::array<uint32_t,8>& k)
{
    std::array<uint8_t,32> out{};

    for (size_t i = 0; i < 8; i++)
    {
        out[i*4 + 0] = static_cast<uint8_t>((k[i] >> 24) & 0xFF);
        out[i*4 + 1] = static_cast<uint8_t>((k[i] >> 16) & 0xFF);
        out[i*4 + 2] = static_cast<uint8_t>((k[i] >> 8) & 0xFF);
        out[i*4 + 3] = static_cast<uint8_t>( k[i]        & 0xFF);
    }

    return out;
}

std::array<uint32_t,8> BytesKeyToArray(const std::array<uint8_t,32>& k)
{
    std::array<uint32_t,8> out;
    for(size_t i = 0; i < 8; i++)
    {
        out[i] = (static_cast<uint32_t>(k[i*4 + 0]) << 24) |
                 (static_cast<uint32_t>(k[i*4 + 1]) << 16) |
                 (static_cast<uint32_t>(k[i*4 + 2]) << 8)  |
                 (static_cast<uint32_t>(k[i*4 + 3]) << 0);
    }
    return out;
}

 std::array<uint8_t,16> genSeed16(){
    std::array<uint8_t,16> seed;
    std::random_device rd;
    for(auto &c: seed) c = static_cast<uint8_t>(rd() & 0xFF);
    return seed;
}

std::array<uint8_t,32> HMAC (std::array<uint8_t,32>& Kin, std::vector<uint8_t>& T)
{
    std::array<uint8_t,64> opad{};
    std::array<uint8_t,64> ipad{};
    std::array<uint8_t,64> KeyBlock{};
    std::fill(opad.begin(), opad.end(),0x5C);
    std::fill(ipad.begin(), ipad.end(), 0x36);
    std::copy(Kin.begin(), Kin.end(), KeyBlock.begin());
    std::fill(KeyBlock.begin() + 32, KeyBlock.end(), 0);
    std::array<uint8_t,64> inner_key{};
    for(size_t i = 0; i < 64; i ++)
    {
        inner_key[i] = KeyBlock[i] ^ ipad[i];
    }
    sha256 inner_sha;

    inner_sha.update(inner_key.data(), inner_key.size() );
    inner_sha.update(T.data(), T.size());
    std::array<uint8_t,32> inner_hash = inner_sha.digest();

    std::array<uint8_t, 64> Kout;
    for (size_t i = 0; i < 64; i++)
    {
        Kout[i] = KeyBlock[i] ^ opad[i];
    }

    sha256 sha_out;
    
    sha_out.update(Kout.data(), Kout.size());
    sha_out.update(inner_hash.data(), inner_hash.size());
    return sha_out.digest();

}
std::array<uint8_t, 32> KDF(std::array<uint32_t,8>& key, std::array<uint8_t,16>& seed)
{
   
    std::array<uint8_t,32> keybytes = keyArrayToBytes(key);


    const std::array<uint8_t,4> label = {0x07, 0xD4, 0x04, 0x14}; 
    const uint8_t separator = 0x00;
 
    const std::array<uint8_t,4> length_be = {0x00, 0x00, 0x00, 0x20}; 

 
    std::vector<uint8_t> T;
    T.reserve(label.size() + 1 + seed.size() + length_be.size() + 1);

    T.insert(T.end(), label.begin(), label.end());
    T.push_back(separator);
    T.insert(T.end(), seed.begin(), seed.end());
    T.insert(T.end(), length_be.begin(), length_be.end());
    uint8_t counter = 0x01;
    T.push_back(counter);

    std::array<uint8_t,32> out = HMAC(keybytes, T);

    return out;
}



