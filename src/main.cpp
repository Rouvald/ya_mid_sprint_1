#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>
#include <string>

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        options.Parse(argc, argv);

        // @note: not find command and didn't raise exception -> it's 'help', just return 0
        if (options.GetCommand() == COMMAND_TYPE::MAX) {
            return 0;
        }

        CryptoGuard::CryptoGuardCtx cryptoCtx;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            std::fstream inFile(options.GetInputFile(), std::ios::in);
            std::fstream outFile(options.GetOutputFile(), std::ios::out);
            cryptoCtx.EncryptFile(inFile, outFile, options.GetPassword());
        } break;
        case COMMAND_TYPE::DECRYPT: {
            std::fstream inFile(options.GetInputFile(), std::ios::in);
            std::fstream outFile(options.GetOutputFile(), std::ios::out);
            cryptoCtx.DecryptFile(inFile, outFile, options.GetPassword());
        } break;
        case COMMAND_TYPE::CHECKSUM: {
            std::fstream inFile(options.GetInputFile(), std::ios::in);
            std::print("Checksum: {}\n", cryptoCtx.CalculateChecksum(inFile));
        } break;
        case COMMAND_TYPE::MAX:
            // @note: this case it's not possible, cos ProgramOptions::Parse has exception on that
            throw std::runtime_error{"Unsupported command"};
        }
    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }
    return 0;
}