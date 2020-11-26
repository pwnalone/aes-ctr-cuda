//
// Copyright (c) 2020 Zakaria Essadaoui, Joshua Inscoe, Alexandra Livadas, Angel Ortiz-Regules
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
// associated documentation files (the "Software"), to deal in the Software without restriction,
// including without limitation the rights to use, copy, modify, merge, publish, distribute,
// sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or
// substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
// NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//


#ifndef AES_HH_
#define AES_HH_


#include <algorithm>
#include <cstdint>


#if defined(__CUDACC__) && defined(__CUDA_ARCH__)
#define CUDA_CALLABLE __host__ __device__
#define CUDA_CONSTANT __constant__
#else
#define CUDA_CALLABLE
#define CUDA_CONSTANT
#endif


namespace crypto {

class Aes128
{
public:
    Aes128(unsigned char const key[16]) noexcept;
    CUDA_CALLABLE void encrypt(unsigned char* block) const noexcept;

    ~Aes128() noexcept;

#ifdef AES_DEBUG_
    void getkeys(uint32_t rks[44]) const noexcept { std::copy_n(rks_, 44, rks); }
#endif

private:
    uint32_t rks_[44];
};

class Aes192
{
public:
    Aes192(unsigned char const key[24]) noexcept;
    CUDA_CALLABLE void encrypt(unsigned char* block) const noexcept;
    ~Aes192() noexcept;

#ifdef AES_DEBUG_
    void getkeys(uint32_t rks[52]) const noexcept { std::copy_n(rks_, 52, rks); }
#endif

private:
    uint32_t rks_[52];
};

class Aes256
{
public:
    Aes256(unsigned char const key[32]) noexcept;
    CUDA_CALLABLE void encrypt(unsigned char* block) const noexcept;
    ~Aes256() noexcept;

#ifdef AES_DEBUG_
    void getkeys(uint32_t rks[60]) const noexcept { std::copy_n(rks_, 60, rks); }
#endif

private:
    uint32_t rks_[60];
};

} // namespace crypto


#endif // ! AES_HH_
