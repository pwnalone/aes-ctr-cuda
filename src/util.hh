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


#ifndef UTIL_HH_
#define UTIL_HH_


#include <algorithm>
#include <climits>
#include <cstdint>
#include <fstream>
#include <functional>
#include <iterator>
#include <random>
#include <string>
#include <type_traits>


namespace { // anonymous

void set_file_contents(char const* filepath, std::string const& bytes)
{
    std::ofstream ofs { };
    ofs.exceptions(std::ofstream::failbit);
    ofs.open(filepath, std::ofstream::out | std::ofstream::binary);

    ofs.write(&bytes[0], bytes.size());

    ofs.close();
}

void get_file_contents(std::string& bytes, char const* filepath, size_t alloc_extra = 0U)
{
    std::ifstream ifs { };
    ifs.exceptions(std::ifstream::failbit);
    ifs.open(filepath, std::ifstream::in | std::ifstream::binary);

    ifs.seekg(0, std::ifstream::end);
    size_t size = ifs.tellg();
    bytes.resize(size + alloc_extra);
    bytes.resize(size);
    ifs.seekg(0, std::ifstream::beg);

    ifs.read(&bytes[0], size);

    ifs.close();
}


template <typename ForwardIter>
void get_random_bytes(ForwardIter begin, ForwardIter end)
{
    using value_type = typename std::iterator_traits<ForwardIter>::value_type;
    static_assert(std::is_unsigned<value_type>::value, "underlying type must be unsigned integral");

    constexpr size_t value_bits = sizeof(value_type) * CHAR_BIT;
    static std::default_random_engine const engine { std::random_device()() };
    std::independent_bits_engine<std::default_random_engine, value_bits, value_type> ibe { engine };
    std::generate(begin, end, std::ref(ibe));
}

} // anonymous namespace


#if defined(__CUDACC__) && defined(__CUDA_ARCH__)
#define CUDA_CALLABLE __host__ __device__
#define CUDA_CONSTANT __constant__
#else
#define CUDA_CALLABLE
#define CUDA_CONSTANT
#endif


namespace crypto {
namespace util {


template <size_t> struct UIntTypesBySize { };

template <> struct UIntTypesBySize<1> { using type =  uint8_t; };
template <> struct UIntTypesBySize<2> { using type = uint16_t; };
template <> struct UIntTypesBySize<4> { using type = uint32_t; };
template <> struct UIntTypesBySize<8> { using type = uint64_t; };


template <typename IntType, size_t N = sizeof(IntType)>
CUDA_CALLABLE inline void to_bytes(
    unsigned char* bytes, typename std::enable_if_t<std::is_integral<IntType>::value, IntType> value
    )
{
    to_bytes<typename UIntTypesBySize<N>::type, N>(bytes, value);
}

template <>
CUDA_CALLABLE inline void to_bytes< uint8_t, 1>(unsigned char* bytes,  uint8_t value)
{
    bytes[0] = (value >>  0) & 0xFF;
}

template <>
CUDA_CALLABLE inline void to_bytes<uint16_t, 2>(unsigned char* bytes, uint16_t value)
{
    bytes[0] = (value >>  8) & 0xFF;
    bytes[1] = (value >>  0) & 0xFF;
}

template <>
CUDA_CALLABLE inline void to_bytes<uint32_t, 4>(unsigned char* bytes, uint32_t value)
{
    bytes[0] = (value >> 24) & 0xFF;
    bytes[1] = (value >> 16) & 0xFF;
    bytes[2] = (value >>  8) & 0xFF;
    bytes[3] = (value >>  0) & 0xFF;
}

template <>
CUDA_CALLABLE inline void to_bytes<uint64_t, 8>(unsigned char* bytes, uint64_t value)
{
    bytes[0] = (value >> 56) & 0xFF;
    bytes[1] = (value >> 48) & 0xFF;
    bytes[2] = (value >> 40) & 0xFF;
    bytes[3] = (value >> 32) & 0xFF;
    bytes[4] = (value >> 24) & 0xFF;
    bytes[5] = (value >> 16) & 0xFF;
    bytes[6] = (value >>  8) & 0xFF;
    bytes[7] = (value >>  0) & 0xFF;
}


template <typename T>
CUDA_CALLABLE inline T min(T a, T b)
{
    return a < b ? a : b;
}

template <typename T>
CUDA_CALLABLE inline T max(T a, T b)
{
    return a > b ? a : b;
}


} // namespace util
} // namespace crypto


#endif // ! UTIL_HH_
