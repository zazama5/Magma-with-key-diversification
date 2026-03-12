    #include <iostream>
    #include <cstdint>
    #include <array>
    #include <iomanip>
    #include <random>
    #include "magma.h"

    const uint8_t pi[8][16] 
    {
        {1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2},
        {8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7},
        {5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0},
        {7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12},
        {12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11},
        {11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0},
        {6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15},
        {12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1}
    };

    std::pair<uint32_t, uint32_t> splitLR(uint64_t block)
    {
        uint32_t L = static_cast<uint32_t>(block >> 32);
        uint32_t R = static_cast<uint32_t>(block & 0xFFFFFFFF);
        return{L,R};
    }

    uint64_t joinLR(uint32_t L, uint32_t R)
    {
        return (static_cast<uint64_t>(L) << 32 | R);
    }

    uint32_t rotate11(uint32_t tmp)
    {
        return (tmp << 11) | (tmp >> (32-11));
    }

    uint32_t substitute(uint32_t x)
    {
        uint32_t y = 0;
        uint32_t nibble_in {}, nibble_out{};
        for (int i =0; i < 8; i++)
        {
            nibble_in = (x >> (4 * (7 - i))) & 0xF;
            nibble_out = pi[i][nibble_in];
            y |= (nibble_out << (4 * (7-i)));
        }
        return y;
    }

    uint32_t round_function(uint32_t R, uint32_t key)
    {
        uint32_t tmp{};
        tmp = R + key;
        tmp = substitute(tmp);
        tmp = rotate11(tmp);
        return tmp;
    }

    void magma_encrypt (uint32_t &L, uint32_t &R, const std::array<uint32_t,8>& keys)
    {
        for(int i =0; i < 24; i++)
        {
            uint32_t tmp = L;
            L = R;
            R = tmp ^ (round_function(L, keys[i%8]));
        }

        for(int j = 7; j >= 0; j--)
        {
            uint32_t tmp = L;
            L = R;
            R = tmp ^ (round_function(L, keys[j]));
        }
    std::swap(R,L);
    }

    void magma_decrypt(uint32_t &L, uint32_t &R, const std::array<uint32_t,8>& keys)
    {
        
        for (int i =0; i < 8; i++)
        {
            uint32_t tmp = L;
            L = R;
            R = tmp ^ (round_function(L, keys[i]));
        }   

        for (int j = 23; j >= 0; j--)
        {
            uint32_t tmp = L;
            L = R;
            R = tmp ^ (round_function(L,keys[j%8]));
        }
        std::swap(R,L);
        
    }

    uint64_t magma_encrypt_block(uint64_t block, const std::array<uint32_t,8>& keys)
    {
        auto [L, R] = splitLR(block);
        magma_encrypt(L, R, keys);
        return joinLR(L,R);
    }

    uint64_t magma_decrypt_block (uint64_t block, const std::array<uint32_t,8>& keys)
    {
        auto [L, R] = splitLR(block);
        magma_decrypt(L, R, keys);
        return joinLR(L,R);
    }

    void run_magma_tests() {
    using std::cout;
    using std::hex;

    auto print64 = [&](uint64_t v){
        cout << std::hex;
        for(int i=7;i>=0;i--){
            uint8_t b = (v >> (i*8)) & 0xFF;
            cout << std::setw(2) << std::setfill('0') << (int)b;
        }
    };

    cout << "=== Тесты ГОСТ Магма ===\n\n";

    // ГОСТовые тестовые ключи
    const std::array<uint32_t,8> keys = {
        0xFFEEDDCC, 0xBBAA9988, 0x77665544, 0x33221100,
        0xF0F1F2F3, 0xF4F5F6F7, 0xF8F9FAFB, 0xFCFDFEFF
    };

    // -------------------------------------------------
    // Тест №1 — ГОСТ Р 34.12-2015, пример для одного блока
    // вход: 0xFEDCBA9876543210
    // ожидаемый результат шифрования:
    // Cipher = 0x4EE901E5C2D8CA3D
    // -------------------------------------------------
    {
        uint64_t block = 0xFEDCBA9876543210ULL;
        uint64_t expected = 0x4EE901E5C2D8CA3DULL;

        uint64_t result = magma_encrypt_block(block, keys);

        cout << "Тест #1 (ГОСТ блок):\n";
        cout << "Вход:       "; print64(block); cout << "\n";
        cout << "Ожидается:  "; print64(expected); cout << "\n";
        cout << "Получено:   "; print64(result); cout << "\n";
        cout << (result == expected ? "OK\n\n" : "ОШИБКА!\n\n");
    }

    // -------------------------------------------------
    // Тест №2 — Проверка decrypt(encrypt) = input
    // -------------------------------------------------
    {
        uint64_t block = 0x0123456789ABCDEFULL;

        uint64_t enc = magma_encrypt_block(block, keys);
        uint64_t dec = magma_decrypt_block(enc, keys);

        cout << "Тест #2 (encrypt+decrypt):\n";
        cout << "Исходный блок: "; print64(block); cout << "\n";
        cout << "After enc/dec: "; print64(dec); cout << "\n";
        cout << (dec == block ? "OK\n\n" : "ОШИБКА!\n\n");
    }

    // -------------------------------------------------
    // Тест №3 — Проверка правильности одного раунда f(R, K)
    // -------------------------------------------------
    {
        uint32_t R = 0x87654321;
        uint32_t K = 0xfedcba98;
        uint32_t expected = 0xfdcbc20c;

        uint32_t result = round_function(R, K);

        cout << "Тест #3 (Раунд):\n";
        cout << "Ожидается: " << std::hex << expected << "\n";
        cout << "Получено:  " << std::hex << result << "\n";
        cout << (result == expected ? "OK\n\n" : "ОШИБКА!\n\n");
    }

    // -------------------------------------------------
    // Тест №4 — Проверка S-box вручную (один пример из ГОСТ)
    // -------------------------------------------------
    {
        uint32_t x = 0xfdb97531;
        uint32_t expected = 0x2a196f34;

        uint32_t result = substitute(x);

        cout << "Тест #4 (S-box):\n";
        cout << "Ожидается: " << std::hex << expected << "\n";
        cout << "Получено:  " << std::hex << result << "\n";
        cout << (result == expected ? "OK\n\n" : "ОШИБКА!\n\n");
    }

  
}

/*int main() {
    run_magma_tests();
    return 0;
}*/