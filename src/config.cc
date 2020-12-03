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


#include "config.hh"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <iostream>

#include <getopt.h>
#include <unistd.h>


#ifndef ENC_PROGRAM
#if defined(RT_PARALLEL) && RT_PARALLEL != 0
#define ENC_PROGRAM "encrypt-par"
#else
#define ENC_PROGRAM "encrypt-seq"
#endif
#endif

#ifndef ENC_VERSION
#define ENC_VERSION "ersion unknown" // This is not a typo.
#endif

#if defined(RT_PARALLEL) && RT_PARALLEL != 0
#define PLATFORM "GPU"
#else
#define PLATFORM "CPU"
#endif


namespace { // anonymous

constexpr char const* const help_string =
    "Usage: " ENC_PROGRAM " [options] [FILE]\n"
    "\n"
    "  Encrypt/decrypt a given file on the " PLATFORM " using AES with the CTR mode of operation.\n"
    "\n"
    "Options:\n"
    "  -h, --help         Display this help menu and exit.\n"
    "  -V, --version      Display the version and exit.\n"
    "  -e, --encrypt      Encrypt the file.\n"
    "  -d, --decrypt      Decrypt the file.\n"
    "  -k KEY, --key KEY  Specify the key to encrypt/decrypt the file.\n"
    "  --128              Encrypt/decrypt the file using a 128-bit AES cipher.\n"
    "  --192              Encrypt/decrypt the file using a 192-bit AES cipher.\n"
    "  --256              Encrypt/decrypt the file using a 256-bit AES cipher [default].\n"
    ;


void help(std::ostream& os)
{
    os << help_string;
}

void vers(std::ostream& os)
{
    os << ENC_PROGRAM " v" ENC_VERSION "\n";
}


Config::UString parse_key(char* ptr)
{
    size_t n = std::strlen(ptr);
    if (n % 2) {
        return { };
    }

    Config::UString key { };
    key.resize(n >> 1);

    // Parse the key as a hex-string.
    for (size_t i = 0; i < n; ++i) {
        if (ptr[i] >= '0' && ptr[i] <= '9') {
            key[i >> 1]  = (ptr[i] - '0' +  0) << 4;
        } else if (ptr[i] >= 'A' && ptr[i] <= 'F') {
            key[i >> 1]  = (ptr[i] - 'A' + 10) << 4;
        } else if (ptr[i] >= 'a' && ptr[i] <= 'f') {
            key[i >> 1]  = (ptr[i] - 'a' + 10) << 4;
        } else {
            return { };
        }
        ++i;
        if (ptr[i] >= '0' && ptr[i] <= '9') {
            key[i >> 1] |= (ptr[i] - '0' +  0) << 0;
        } else if (ptr[i] >= 'A' && ptr[i] <= 'F') {
            key[i >> 1] |= (ptr[i] - 'A' + 10) << 0;
        } else if (ptr[i] >= 'a' && ptr[i] <= 'f') {
            key[i >> 1] |= (ptr[i] - 'a' + 10) << 0;
        } else {
            return { };
        }
    }

    return key;
}

} // anonymous namespace


int Config::parse(int argc, char* const argv[]) noexcept
{
    if (argc < 2) {
        help(std::cout);
        return 0;
    }

    while (1) {
        static constexpr struct option const long_options[] =
        {
            {    "help",       no_argument, nullptr, 'h' },
            { "version",       no_argument, nullptr, 'V' },
            { "encrypt",       no_argument, nullptr, 'e' },
            { "decrypt",       no_argument, nullptr, 'd' },
            {     "key", required_argument, nullptr, 'k' },
            {     "128",       no_argument, nullptr, 128 },
            {     "192",       no_argument, nullptr, 192 },
            {     "256",       no_argument, nullptr, 256 },
            {   nullptr,                 0, nullptr,   0 }
        };

        static constexpr char const* ex_key = "00112233445566778899aabbccddeeff";

        int c = getopt_long(argc, argv, ":hVedk:", long_options, nullptr);
        if (c < 0) {
            break;
        }

        switch (c) {
        case 'h':
            help(std::cout);
            return 0;
        case 'V':
            vers(std::cout);
            return 0;

        case 'e':
            if (op == Operation::kDecrypt) {
                std::cerr << ENC_PROGRAM ": Options -e and -d are mutually-exclusive\n";
                return -2;
            }
            op = Operation::kEncrypt;
            break;
        case 'd':
            if (op == Operation::kEncrypt) {
                std::cerr << ENC_PROGRAM ": Options -e and -d are mutually-exclusive\n";
                return -2;
            }
            op = Operation::kDecrypt;
            break;

        case 'k':
            if (!key.empty()) {
                std::cerr << ENC_PROGRAM ": Option -k may only be specified one time\n";
                return -2;
            }
            key = parse_key(optarg);
            if ( key.empty()) {
                std::cerr << ENC_PROGRAM ": AES key must be hex-encoded -- e.g. \"" << ex_key << "\"\n";
                return -2;
            }
            break;

        case 128:
        case 192:
        case 256:
            switch (key_size ^ c) {
            case 128 ^ 192:
                std::cerr << ENC_PROGRAM ": Options --128 and --192 are mutually-exclusive\n";
                return -2;
            case 128 ^ 256:
                std::cerr << ENC_PROGRAM ": Options --128 and --256 are mutually-exclusive\n";
                return -2;
            case 192 ^ 256:
                std::cerr << ENC_PROGRAM ": Options --192 and --256 are mutually-exclusive\n";
                return -2;
            }
            key_size = c;
            break;

        case ':':
            std::cerr << ENC_PROGRAM ": Missing option \'"  << argv[optind - 1] << "\' argument\n";
            return -2;
        case '?':
            if (optopt) {
                std::cerr << ENC_PROGRAM ": Unknown option \'-" << static_cast<char>(optopt) << "\'\n";
            } else {
                std::cerr << ENC_PROGRAM ": Unknown option \'"  << argv[optind - 1] << "\'\n";
            }
            return -2;

        default:
            assert("Unhandled option" && false);
            return -2;
        }
    }

    if (op == Operation::kUnknown) {
        std::cerr << ENC_PROGRAM ": One of options -e and -d must be specified\n";
        return -2;
    }
    if (op == Operation::kDecrypt && key.empty()) {
        std::cerr << ENC_PROGRAM ": Option -d requires that a key be specified\n";
        return -2;
    }

    if (key_size == 0) {
        key_size = (key.size() > 0) ? key.size() * 8 : 256;
    }
    if (key_size != key.size() * 8 && !key.empty()) {
        std::cerr << ENC_PROGRAM ": AES key must be appropriately sized\n";
        return -2;
    }

    if (argc - optind < 1) {
        std::cerr << ENC_PROGRAM ": Missing argument \'FILE\'\n";
        return -2;
    }
    if (argc - optind > 1) {
        std::cerr << ENC_PROGRAM ": Trailing arguments --";
        std::for_each(argv + optind, argv + argc, [](char const* argval) {
            std::cerr << " " << argval;
        });
        std::cerr << "\n";
        return -2;
    }

    filepath = argv[optind];

    return 1;
}
