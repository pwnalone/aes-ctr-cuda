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


#ifndef FSC_HH_
#define FSC_HH_


#include <cstdint>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <type_traits>

#include "util.hh"


#if defined(__CUDACC__) && defined(__CUDA_ARCH__)
#define CUDA_CALLABLE __host__ __device__
#define CUDA_CONSTANT __constant__
#else
#define CUDA_CALLABLE
#define CUDA_CONSTANT
#endif


namespace crypto {


template <size_t Size>
class FixedSizeCounter
{
public:
    CUDA_CALLABLE FixedSizeCounter() noexcept { std::memset(data, 0x00, Size); }

    template <
        typename IntType,
        typename = typename std::enable_if_t<
            std::is_integral<IntType>::value && std::less_equal<size_t>()(sizeof(IntType), Size)
            >
        >
    CUDA_CALLABLE FixedSizeCounter(IntType val) noexcept
    {
        if (sizeof(IntType) < Size) {
            // Perform sign-extention by filling the most-significant bytes of `data` with 0x00 or
            // 0xff bytes, formed by right-shifting in 8 sign bits from `val`.
            int sbits = static_cast<std::make_signed_t<IntType>>(val) >> (8 * sizeof(IntType) - 1);
            std::memset(data, sbits & 0xff, Size - sizeof(IntType));
        }
        util::to_bytes<IntType>(data + Size - sizeof(IntType), val);
    }

    CUDA_CALLABLE FixedSizeCounter(unsigned char const* bytearr, size_t a_size)
    {
#if !defined(__CUDA_ARCH__)
        if (a_size > Size) {
            throw std::runtime_error("FixedSizeCounter() received out of bounds size parameter");
        }
#endif
        // FIXME: Move the below code into an `init()` helper function.
        if (a_size < Size) {
            int sbits = static_cast<char>(bytearr[0]) >> 7;
            std::memset(data, sbits & 0xff, Size - a_size);
        }
        std::memcpy(data + Size - a_size, bytearr, a_size);
    }

    template <size_t SizeLe, typename = typename std::enable_if_t<std::less_equal<size_t>()(SizeLe, Size)>>
    CUDA_CALLABLE FixedSizeCounter(FixedSizeCounter<SizeLe> const& rhs) noexcept
        : FixedSizeCounter<Size>(rhs.data, SizeLe) { }

    template <size_t SizeLe, typename = typename std::enable_if_t<std::less_equal<size_t>()(SizeLe, Size)>>
    CUDA_CALLABLE FixedSizeCounter<Size>& operator= (FixedSizeCounter<SizeLe> const& rhs) noexcept
    {
        unsigned char const* bytearr = rhs.data;
        // FIXME: Move the below code into an `init()` helper function.
        if (SizeLe < Size) {
            int sbits = static_cast<char>(bytearr[0]) >> 8;
            std::memset(data, sbits & 0xff, Size - SizeLe);
        }
        std::memcpy(data + Size - SizeLe, bytearr, SizeLe);
    }

    template <size_t SizeLe, typename = typename std::enable_if_t<std::less_equal<size_t>()(SizeLe, Size)>>
    CUDA_CALLABLE FixedSizeCounter<Size>& operator+=(FixedSizeCounter<SizeLe> const& rhs) noexcept
    {
        do_add<SizeLe>(data, rhs.data);
        return *this;
    }
    template <
        typename IntType,
        typename = typename std::enable_if_t<
            std::is_integral<IntType>::value && std::less_equal<size_t>()(sizeof(IntType), Size)
            >
        >
    CUDA_CALLABLE FixedSizeCounter<Size>& operator+=(IntType rhs) noexcept
    {
        return *this += FixedSizeCounter<Size>(rhs);
    }

    template <size_t SizeLe, typename = typename std::enable_if_t<std::less_equal<size_t>()(SizeLe, Size)>>
    CUDA_CALLABLE friend FixedSizeCounter<Size  > operator+(
        FixedSizeCounter<Size> lhs, FixedSizeCounter<SizeLe> const& rhs
        )
    {
        return lhs += rhs;
    }
    template <size_t SizeGt, typename = typename std::enable_if_t<std::less<size_t>()(Size, SizeGt)>>
    CUDA_CALLABLE friend FixedSizeCounter<SizeGt> operator+(
        FixedSizeCounter<Size> const& lhs, FixedSizeCounter<SizeGt> rhs
        )
    {
        return rhs += lhs;
    }
    template <
        typename IntType,
        typename = typename std::enable_if_t<
            std::is_integral<IntType>::value && std::less_equal<size_t>()(sizeof(IntType), Size)
            >
        >
    CUDA_CALLABLE friend FixedSizeCounter<Size  > operator+(
        FixedSizeCounter<Size> lhs, IntType rhs
        )
    {
        return lhs += rhs;
    }

    CUDA_CALLABLE FixedSizeCounter<Size>& operator++(   ) noexcept
    {
        do_inc(data);
        return *this;
    }
    CUDA_CALLABLE FixedSizeCounter<Size>  operator++(int) noexcept
    {
        FixedSizeCounter<Size> other { *this };
        do_inc(data);
        return other;
    }

private:
    CUDA_CALLABLE static void do_inc(
        unsigned char lhs[Size], size_t start = 0, unsigned char carry = 1
        )
    {
        for (size_t i = Size - start; i > 0; --i) {
            lhs[i - 1] += carry;
            carry = static_cast<unsigned char>(lhs[i - 1] < carry);
        }
    }

    template <size_t SizeLe, typename = typename std::enable_if_t<std::less_equal<size_t>()(SizeLe, Size)>>
    CUDA_CALLABLE static void do_add(unsigned char lhs[Size], unsigned char const rhs[SizeLe])
    {
        unsigned char carry = 0;
        for (size_t i = SizeLe; i > 0; --i) {
            lhs[i - 1] += rhs[i - 1] + carry;
            carry &= static_cast<unsigned char>(lhs[i - 1] == rhs[i - 1]);
            carry |= static_cast<unsigned char>(lhs[i - 1] <  rhs[i - 1]);
        }
        do_inc(lhs, SizeLe, carry);
    }

public:
    CUDA_CALLABLE constexpr size_t size() const noexcept
    {
        return Size;
    }

public:
    unsigned char data[Size];
};


} // namespace crypto


#endif // ! FSC_HH_
