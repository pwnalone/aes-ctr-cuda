//
// Copyright (c) 2018 Zakaria Essadaoui, Joshua Inscoe, Alexandra Livadas, Angel Ortiz-Regules
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


#ifndef CTR_HH_
#define CTR_HH_


#include <algorithm>

#include "aes.hh"
#include "fsc.hh"
#include "util.hh"


#if defined(__CUDACC__) && defined(__CUDA_ARCH__)
#define CUDA_CALLABLE __host__ __device__
#define CUDA_CONSTANT __constant__
#else
#define CUDA_CALLABLE
#define CUDA_CONSTANT
#endif


namespace crypto {


template <typename BlockCipherType>
class CtrMode
{
public:
    using cipher_type = BlockCipherType;
    static constexpr size_t blk_size = BlockCipherType::blk_size;
    static constexpr size_t key_size = BlockCipherType::key_size;

    CtrMode(unsigned char const key[key_size]) noexcept : cipher_(key), nonce_() { }

    CtrMode(unsigned char const key[key_size], unsigned char const nonce[blk_size]) noexcept
        : cipher_(key)
    {
        std::copy_n(nonce, blk_size, nonce_);
    }

    CUDA_CALLABLE void encrypt(unsigned char* data, size_t size, size_t init) const noexcept
    {
        FixedSizeCounter<blk_size> ctr = FixedSizeCounter<blk_size>(nonce_, blk_size) + init;
        for (auto ptr = data; size > 0; size -= util::min(blk_size, size), ptr += blk_size) {
            FixedSizeCounter<blk_size> tmp = ctr;
            cipher_.encrypt(tmp.data);
            for (size_t i = 0; i < util::min(blk_size, size); ++i) {
                ptr[i] ^= tmp.data[i];
            }
            ++ctr;
        }
    }

private:
    cipher_type cipher_;
    unsigned char nonce_[blk_size];
};


} // namespace crypto


#endif // ! CTR_HH_
