#pragma once
#include <cstdint>

extern const uint8_t pi[8][16];
std::pair<uint32_t, uint32_t> splitLR(uint64_t block);//Делим блок на 2 части
uint64_t joinLR(uint32_t L, uint32_t R);//Собираем из 2 частей блок
uint32_t rotate11(uint32_t tmp);//Циклический сдвиг на 11 
uint32_t substitute(uint32_t x);//Меняем ниблы
uint32_t round_function(uint32_t R, uint32_t key);//Раундовая функция

void magma_encrypt (uint32_t &L, uint32_t &R, const std::array<uint32_t,8>& keys);//Шифрование магмой принимающей L и R
void magma_decrypt(uint32_t &L, uint32_t &R, const std::array<uint32_t,8>& keys);//Дешифрование магмой принимающей L и R
uint64_t magma_encrypt_block(uint64_t block, const std::array<uint32_t,8>& keys);//Нормальная магма которая уже принимает блоки
uint64_t magma_decrypt_block (uint64_t block, const std::array<uint32_t,8>& keys);//Нормальная магма которая уже принимает блоки