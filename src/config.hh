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


#ifndef CONFIG_HH_
#define CONFIG_HH_


#include <string>


struct Config
{
    using UString = std::basic_string<unsigned char>;

    enum class Operation { kUnknown = 0, kEncrypt, kDecrypt };

#if defined(RT_PARALLEL) && RT_PARALLEL != 0
    Config() noexcept
        : filepath(nullptr), key(), key_size(0U), op(Operation::kUnknown), nb(0U), nt(0U) { }
#else
    Config() noexcept : filepath(nullptr), key(), key_size(0U), op(Operation::kUnknown) { }
#endif

    int parse(int argc, char* const argv[]) noexcept;

    char const* filepath;
    UString     key;
    size_t      key_size;
    Operation   op;
#if defined(RT_PARALLEL) && RT_PARALLEL != 0
    size_t      nb;
    size_t      nt;
#endif
};


#endif // ! CONFIG_HH_
