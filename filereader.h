#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <fstream>

class FileReader 
{
public:
    FileReader(const std::string& filename);
    ~FileReader();

    bool open(const std::string& filename);
    bool isOpen() const;
    void close();

    std::vector<uint8_t> read();
    bool eof() const;

private:
    std::ifstream stream;
    const size_t bufferSize = 4096;
};
