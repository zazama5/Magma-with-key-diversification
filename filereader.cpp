#include <iostream>
#include <fstream>
#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include "filereader.h"

FileReader::FileReader(const std::string& filename)
{
    if (!open(filename))
        throw std::runtime_error("Не удалось открыть файл");
}

FileReader::~FileReader()
{
    close();
}

bool FileReader::open(const std::string& filename)
{
    stream.open(filename, std::ios::binary);
    return stream.is_open();
}

void FileReader::close()
{
    if (stream.is_open())
        stream.close();
}

bool FileReader::isOpen() const
{
    return stream.is_open();
}

std::vector<uint8_t> FileReader::read()
{
    std::vector<uint8_t> buffer(bufferSize);
    if (!stream.read(reinterpret_cast<char*>(buffer.data()), bufferSize))
        buffer.resize(stream.gcount());
    return buffer;
}

bool FileReader::eof() const
{
    return stream.eof();
}

