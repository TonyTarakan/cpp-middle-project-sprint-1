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

        auto getFileStream = [](const std::string &path, const std::ios::openmode mode) {
            std::fstream f{path, mode};
            if (!f.is_open()) {
                throw std::runtime_error{std::format("File '{}' error", path)};
            }
            return f;
        };

        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;

        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            std::fstream in = getFileStream(options.GetInputFile(), std::ios::in);
            std::fstream out = getFileStream(options.GetOutputFile(), std::ios::out);
            cryptoCtx.EncryptFile(in, out, options.GetPassword());
            std::print("File encoded successfully\n");
            break;
        }
        case COMMAND_TYPE::DECRYPT: {
            std::fstream in = getFileStream(options.GetInputFile(), std::ios::in);
            std::fstream out = getFileStream(options.GetOutputFile(), std::ios::out);
            cryptoCtx.DecryptFile(in, out, options.GetPassword());
            std::print("File decoded successfully\n");
            break;
        }
        case COMMAND_TYPE::CHECKSUM: {
            std::fstream in = getFileStream(options.GetInputFile(), std::ios::in);
            std::print(std::cout, "Checksum: {}\n", cryptoCtx.CalculateChecksum(in));
            break;
        }
        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Exit: {}\n", e.what());
        return 1;
    }

    return 0;
}
