#include "cmd_options.h"
#include <iostream>
#include <optional>
#include <print>

namespace {
constexpr auto helpOp{"help"};
constexpr auto commandOp{"command"};
constexpr auto inputOp{"input"};
constexpr auto outputOp{"output"};
constexpr auto passwordOp{"password"};
}  // namespace

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    // @note: can't use '*Op' vars, cos options have short version
    desc_.add_options()                //
        ("help,h", "Print help info")  //
        ("command,c", po::value<std::string>(),
         "command to execute: encrypt, decrypt and checksum")                //
        ("input,i", po::value<std::string>(), "Path to input file")          //
        ("output,o", po::value<std::string>(), "Path to output file")        //
        ("password,p", po::value<std::string>(), "Password for enc or dec")  //
        ;
}

ProgramOptions::~ProgramOptions() = default;

std::optional<std::string> ProgramOptions::Parse(int argc, char *argv[]) {
    const auto PrintHelp = [this]() { std::cout << desc_ << "\n"; };

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);
    po::notify(vm);

    // @note: app use only with params
    if (vm.empty()) {
        return {"App called without options!\n"};
    }
    for (const auto &[optName, val] : vm) {
        if (optName == helpOp) {
            PrintHelp();
            return {""};
        } else if (optName == commandOp) {  // @todo: mb need refactor?! cos dup logic
            command_ = commandMapping_.at(vm[commandOp].as<std::string>());
        } else if (optName == inputOp) {
            inputFile_ = vm[inputOp].as<std::string>();
        } else if (optName == outputOp) {
            outputFile_ = vm[outputOp].as<std::string>();
        } else if (optName == passwordOp) {
            password_ = vm[passwordOp].as<std::string>();
        }
    }
    return std::nullopt;
}

}  // namespace CryptoGuard
