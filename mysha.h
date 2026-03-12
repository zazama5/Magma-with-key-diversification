#pragma once
#include <iostream>
#include <cstdint>
#include <array>
#include <iomanip>
#include <vector>
#include <cstring>
#include <fstream>
#include <sstream>

struct sha256_family
{
    using word_t = uint32_t;
    static constexpr size_t BLOCK_SIZE = 64;
    static constexpr size_t ROUNDS = 64;
    static constexpr size_t LENGTH_BYTES = 8;
    static constexpr std::array<word_t, 64> K = {
           0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
           0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
           0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
           0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
           0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
           0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
           0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
           0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
           0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
           0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
           0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
           0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
           0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
           0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
           0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
           0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
    };
    static word_t sigma0(word_t x) { return ROTR(x,7) ^ ROTR(x,18) ^ SHR(x,3); }
    static word_t sigma1(word_t x) { return ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10); }
    static word_t bigSigma0(word_t x) { return ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22); }
    static word_t bigSigma1(word_t x) { return ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25); }
    static word_t Ch(word_t x, word_t y, word_t z) { return (x & y) ^ (~x & z); }
    static word_t Maj(word_t x, word_t y, word_t z) { return (x & y) ^ (x & z) ^ (y & z); }

    static word_t ROTR(word_t x, int n) { return (x >> n) | (x << (32 - n)); }
    static word_t SHR(word_t x, int n) { return x >> n;}
};

struct sha512_family
{
    using word_t = uint64_t;
    static constexpr size_t BLOCK_SIZE = 128;
    static constexpr size_t ROUNDS = 80;
    static constexpr size_t LENGTH_BYTES = 16;
    static constexpr std::array<word_t, 80> K = {
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    };

    static word_t sigma0(word_t x) { return ROTR(x,1) ^ ROTR(x,8) ^ SHR(x,7); }
    static word_t sigma1(word_t x) { return ROTR(x,19) ^ ROTR(x,61) ^ SHR(x,6); }
    static word_t bigSigma0(word_t x) { return ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39); }
    static word_t bigSigma1(word_t x) { return ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41); }
    static word_t Ch(word_t x, word_t y, word_t z) { return (x & y) ^ (~x & z); }
    static word_t Maj(word_t x, word_t y, word_t z) { return (x & y) ^ (x & z) ^ (y & z); }

    static word_t ROTR(word_t x, int n) { return (x >> n) | (x << (64 - n)); }
    static word_t SHR(word_t x, int n) { return x >> n;}
};

template<typename Traits>

class SHA2
{
    public: 
    using word_t = typename Traits::word_t;
    static constexpr size_t BLOCK_SIZE = Traits::BLOCK_SIZE;

    SHA2(const std::array<word_t, 8>& iv): H(iv), buffer{0},bufferSize{0}, totalBits{0}{}

    void update(const uint8_t* data, size_t len)
    {
        size_t i = 0;
        if (bufferSize > 0)
            {
                size_t need = BLOCK_SIZE - bufferSize;

                if (len >= need)
                {
                    memcpy(buffer.data() + bufferSize, data, need);
                    totalBits += need*8;
                    processBlock(buffer.data());
                    bufferSize = 0; 
                    i += need;
                }

                else
                {
                    memcpy(buffer.data() + bufferSize, data, len);
                    bufferSize += len;
                    totalBits += len * 8;
                    return;
                }
            }

        for (; i + BLOCK_SIZE <= len; i += BLOCK_SIZE)
        {
        processBlock(data + i);
        totalBits += BLOCK_SIZE * 8;
        }

        if (i < len)
        {
            bufferSize = len - i;
            memcpy(buffer.data(), data + i, bufferSize);
            totalBits += bufferSize * 8;
        }
        
    }

    void finalize()
    {
        const size_t LENGTH_BYTES = Traits::LENGTH_BYTES;
        const size_t BIT_LENGTH_OFFSET = BLOCK_SIZE - LENGTH_BYTES;
        buffer.at(bufferSize++) = 0x80;
        if (bufferSize > BIT_LENGTH_OFFSET)
        {
            for (size_t i = bufferSize; i < BLOCK_SIZE; i++)
            buffer.at(i) = 0;

            processBlock(buffer.data());
            bufferSize = 0;
        }

        for (size_t i = bufferSize; i < BIT_LENGTH_OFFSET; i++)
            buffer.at(i) = 0;
        
        for (size_t i = 0; i < LENGTH_BYTES; i++)
        {
            buffer.at(BLOCK_SIZE - 1 - i) =
            static_cast<uint8_t>((totalBits >> (8 * i)) & 0xFF);
        }

        processBlock(buffer.data());
        bufferSize = 0;
        
}

    protected:

    std::array<word_t, 8> H;
    std::array<uint8_t, BLOCK_SIZE> buffer;
    size_t bufferSize;
    typedef __int128 uint128_t;
    uint128_t totalBits;

    static word_t zagruzka_slov(const uint8_t* data) {
        if constexpr (sizeof(word_t) == 4) {
            return (static_cast<word_t>(data[0]) << 24) |
                   (static_cast<word_t>(data[1]) << 16) |
                   (static_cast<word_t>(data[2]) << 8) |
                   (static_cast<word_t>(data[3]));
        } else if constexpr (sizeof(word_t) == 8) {
            return (static_cast<word_t>(data[0]) << 56) |
                   (static_cast<word_t>(data[1]) << 48) |
                   (static_cast<word_t>(data[2]) << 40) |
                   (static_cast<word_t>(data[3]) << 32) |
                   (static_cast<word_t>(data[4]) << 24) |
                   (static_cast<word_t>(data[5]) << 16) |
                   (static_cast<word_t>(data[6]) << 8) |
                   (static_cast<word_t>(data[7]));
        }
        return 0;
    }
    void processBlock (const uint8_t* data)
    {
        std::array<word_t, Traits::ROUNDS> W{};

        for(size_t t = 0; t < 16; t++)
      W[t] = zagruzka_slov(data + t * sizeof(word_t));

        for(size_t t = 16; t < Traits::ROUNDS; t++)
        {
            W[t] = Traits::sigma1(W[t - 2]) + W[t - 7] + Traits::sigma0(W[t - 15]) + W[t - 16];
        }
        
        word_t a = H[0], b = H[1], c = H[2], d = H[3],
               e = H[4], f = H[5], g = H[6], h = H[7];
        
        for (size_t t = 0; t < Traits::ROUNDS; t++)
        {
            word_t T1 = h + Traits::bigSigma1(e) +  Traits::Ch(e, f, g) + Traits::K[t] + W[t];
            word_t T2 = Traits::bigSigma0(a) + Traits::Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
        
    }
    
    
    

};

class sha256: public SHA2<sha256_family>
{

    public:
    sha256(): SHA2<sha256_family>(iv){}
    std::array<uint8_t,32> digest() const
    {
    std::array<uint8_t,32> out;

    for (int i = 0; i < 8; i++)
    {
        out[i*4 + 0] = (H[i] >> 24) & 0xFF;
        out[i*4 + 1] = (H[i] >> 16) & 0xFF;
        out[i*4 + 2] = (H[i] >> 8) & 0xFF;
        out[i*4 + 3] = (H[i] >> 0) & 0xFF;
    }

    return out;
    }

    private:
    static constexpr std::array<uint32_t, 8> iv = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

};

class sha224: public SHA2<sha256_family>
{
    public:
    sha224(): SHA2<sha256_family>(iv){}
    std::array<uint8_t,28> digest() const
    {
    std::array<uint8_t,28> out;

    for (int i = 0; i < 7; i++)
    {
        out[i*4 + 0] = (H[i] >> 24) & 0xFF;
        out[i*4 + 1] = (H[i] >> 16) & 0xFF;
        out[i*4 + 2] = (H[i] >> 8) & 0xFF;
        out[i*4 + 3] = (H[i] >> 0) & 0xFF;
    }

    return out;
    }
    
    private:
    static constexpr std::array<uint32_t,8> iv = {0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
                                                  0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4};
};

class sha512: public SHA2<sha512_family>
{
    public:
    sha512():SHA2<sha512_family>(iv){}
    std::array<uint8_t,64> digest() const
    {
        std::array<uint8_t, 64> out;
        for (int i = 0; i < 64; i++)
        {
            out[i] = (H[i/8] >> (56 - (i%8)*8)) & 0xFF; 
        }
    return out;
    }
    private:
    static constexpr std::array<uint64_t,8> iv = {0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
                                                  0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179};
};

class sha384: public SHA2<sha512_family>
{
    public:
    sha384():SHA2<sha512_family>(iv){}
    std::array<uint8_t,48> digest() const
    {
        std::array<uint8_t, 48> out;
        for (int i = 0; i < 48; i++)
        {
            out[i] = (H[i/8] >> (56 - (i%8)*8)) & 0xFF; 
        }
    return out;
    }
    private:
    static constexpr std::array<uint64_t,8> iv = {0xCBBB9D5DC1059ED8, 0x629A292A367CD507, 0x9159015A3070DD17, 0x152FECD8F70E5939,
                                                  0x67332667FFC00B31, 0x8EB44A8768581511, 0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4};
};

class sha512_256: public SHA2<sha512_family>
{
    public:
    sha512_256():SHA2<sha512_family>(iv){}
    std::array<uint8_t,32> digest() const
    {
        std::array<uint8_t, 32> out;
        for (int i = 0; i < 32; i++)
        {
            out[i] = (H[i/8] >> (56 - (i%8)*8)) & 0xFF; 
        }
    return out;
    }
    private:
    static constexpr std::array<uint64_t,8> iv = {
        0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD,
        0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2
    };
};

class sha512_224: public SHA2<sha512_family>
{
    public:
    sha512_224():SHA2<sha512_family>(iv){}
    std::array<uint8_t,28> digest() const
    {
        std::array<uint8_t, 28> out;
        for (int i = 0; i < 28; i++)
        {
            out[i] = (H[i/8] >> (56 - (i%8)*8)) & 0xFF; 
        }
    return out;
    }
    private:
    static constexpr std::array<uint64_t,8> iv = {
        0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF,
        0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1
    };
};



