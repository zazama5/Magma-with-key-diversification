#include "file_utils.h"
#include <fstream>
#include <cstdint>
#include <string>
#include <vector>
#include <array>

std::vector<uint8_t> readFile (const std::string& filename)
{
    std::ifstream file (filename, std::ios::binary);
    if (!file) throw std::runtime_error("Не удалось открыть файл");
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), {});
}

void writeFile(const std::string &filename, const std::vector<uint8_t> & data)
{
    std::ofstream file (filename, std::ios::binary);
    if (!file) throw std::runtime_error("Не удалось открыть файл на запись");
    file.write(reinterpret_cast<const char*>(data.data()),data.size());
}


std::vector<uint64_t> splitBlocksForEncrypt (const std::vector<uint8_t>& data)
{
    std::vector<uint64_t> blocks {};
    size_t fullBlocks = data.size() / 8;
    size_t remainder = data.size() % 8;

    
    for (size_t i = 0; i < fullBlocks; i++)
    {
        uint64_t block{};
        for(int j = 0; j < 8; j++)
        {
            block |= static_cast<uint64_t>(data[j + (i *8)]) << (8 * (7 - j));
        }
        blocks.push_back(block);
    }

    uint8_t buffer[8] = {0};
    uint8_t pad = (remainder == 0 )? 8 : (8 - remainder);

    for(size_t i =0; i <remainder; i++)
    {
        buffer[i]= data[fullBlocks * 8 + i];
    }

    for(int j = remainder; j < 8; j++)
    {
        buffer[j] = pad;
    }

    uint64_t lastBlock = 0;
    for (int i = 0; i < 8; i++)
    {
        lastBlock |= static_cast<uint64_t> (buffer[i]) << (8 * ( 7 - i));
    }

    blocks.push_back(lastBlock);

    return blocks;
}

std::vector<uint64_t> splitBlocksForDecrypt (const std::vector<uint8_t>& data)
{
    if (data.size() % 8 != 0) throw std::runtime_error("Размер файла не делится на 8");
    std::vector<uint64_t> blocks;
    size_t size = (data.size() / 8);
    blocks.reserve(size);
    for ( size_t i = 0; i < size; i++)
    {
        uint64_t block{};
        for (int j = 0; j < 8; j++)
        {
            block |= static_cast<uint64_t> (data[8 * i +j]) << (8 * (7-j));
        }
        blocks.push_back(block);
    }
    return blocks;
}




std::vector<uint8_t> joinBlocksForDecrypt(const std::vector<uint64_t> &blocks)
{
    std::vector<uint8_t> data;
    for (uint64_t block : blocks)
    {
        for (int i= 0; i < 8; i++)
       {
        uint8_t byte =static_cast<uint8_t>((block >> (8 * (7 - i))) & 0xFF);
        data.push_back(byte);
       }
    }

    if (!data.empty())
    {
        uint8_t pad = data.back();
        if (pad > 0 && pad <= 8)
        {
            bool valid = true;
            for (int i = 0; i < pad; ++i)
            {
                if (data[data.size() - 1 - i] != pad)
                {
                    valid = false;
                    break;
                }
            }
            if (valid)
                data.resize(data.size() - pad);
        }
    }

    return data;
}

std::vector<uint8_t> joinBlocksForEncrypt(const std::vector<uint64_t> &blocks)
{
    std::vector<uint8_t> data;
    for (uint64_t block : blocks)
    {
        for (int i= 0; i < 8; i++)
       {
        uint8_t byte =static_cast<uint8_t>((block >> (8 * (7 - i))) & 0xFF);
        data.push_back(byte);
       }
    }
    return data;
}

