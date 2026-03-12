#include <iostream>
#include <vector>
#include <cstdint>
#include <array>
#include <string>
#include "magma.h"
#include "cbc.h"


std::vector<uint64_t> encryptCBC(const std::vector<uint64_t>& blocks, uint64_t IV, const std::array<uint32_t,8>& keys)
{
    std::vector<uint64_t> out{};
    out.reserve(blocks.size());
    uint64_t prev = IV;
    for (size_t i = 0; i < blocks.size(); i++)
    {
        uint64_t x = blocks[i] ^ prev;
        x = magma_encrypt_block(x, keys);
        out.push_back(x);
        prev = x;
    }
    return out;
}

std::vector<uint64_t> decryptCBC(const std::vector<uint64_t>& cblocks, uint64_t IV, const std::array<uint32_t,8>& keys)
{
    std::vector<uint64_t> out{};
    out.reserve(cblocks.size());
    uint64_t prev = IV;
    for (size_t j = 0; j < cblocks.size(); j++)
    {
        uint64_t y = magma_decrypt_block(cblocks[j], keys);
        y^= prev;
        out.push_back(y);
        prev = cblocks[j];
    }
    return out;
}