#pragma once

#include <boost/program_options.hpp>
#include <cstdint>
#include <string>
#include <unordered_map>

namespace CryptoGuard {
namespace po = boost::program_options;

namespace CommandTypeStr {
constexpr auto encCom{"encrypt"};
constexpr auto decCom{"decrypt"};
constexpr auto checkCom{"checksum"};
}  // namespace CommandTypeStr

class ProgramOptions {
public:
    ProgramOptions();
    ~ProgramOptions();

    enum class COMMAND_TYPE : uint8_t {
        ENCRYPT = 0,
        DECRYPT,
        CHECKSUM,

        MAX
    };

    void Parse(int argc, char *argv[]);

    COMMAND_TYPE GetCommand() const { return command_; }
    std::string GetInputFile() const { return inputFile_; }
    std::string GetOutputFile() const { return outputFile_; }
    std::string GetPassword() const { return password_; }

private:
    COMMAND_TYPE command_{COMMAND_TYPE::MAX};
    const std::unordered_map<std::string_view, COMMAND_TYPE> commandMapping_ = {
        {CommandTypeStr::encCom, ProgramOptions::COMMAND_TYPE::ENCRYPT},
        {CommandTypeStr::decCom, ProgramOptions::COMMAND_TYPE::DECRYPT},
        {CommandTypeStr::checkCom, ProgramOptions::COMMAND_TYPE::CHECKSUM},
    };

    std::string inputFile_;
    std::string outputFile_;
    std::string password_;

    po::options_description desc_;
};

}  // namespace CryptoGuard
