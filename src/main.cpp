#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <algorithm>
#include <array>
#include <iostream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>
#include <string>

int main(int argc, char *argv[]) {
    try {

        CryptoGuard::ProgramOptions options;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        const auto parseRes = options.Parse(argc, argv);
        if (parseRes) {
            // @note: if empty -> called option HELP -> exit 0
            if (parseRes.value().empty()) {
                return 0;
            } else {
                throw std::runtime_error{parseRes.value()};
            }
        }
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT:
        case COMMAND_TYPE::DECRYPT:
        case COMMAND_TYPE::CHECKSUM:
            // skip or print some info, like "u choose 'com_name' command"
            break;

        case COMMAND_TYPE::MAX:
            throw std::runtime_error{"Unsupported command"};
        }
        CryptoGuard::CryptoGuardCtx cryptoCtx;
    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}