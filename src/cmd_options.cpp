#include "cmd_options.h"
#include <boost/program_options/errors.hpp>
#include <iostream>
#include <stdexcept>
#include <string>

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
        ("command,c", po::value<std::string>()->required(),
         "command to execute: encrypt, decrypt and checksum")                    //
        ("input,i", po::value<std::string>()->required(), "Path to input file")  //
        ("output,o", po::value<std::string>(), "Path to output file")            //
        ("password,p", po::value<std::string>(), "Password for enc or dec")      //
        ;
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    const auto PrintHelp = [this]() { std::cout << desc_ << "\n"; };

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);

    // @note: app use only with params
    if (vm.empty()) {
        throw std::runtime_error("App called without options!");
    }
    if (vm.count(helpOp)) {
        PrintHelp();
        return;
    }
    // @note: cos this raise exception -> process "help" before it
    // @note: raise throw po::required_option if has not options 'command' and 'input' -> cos they a default
    po::notify(vm);

    const auto commandName = vm[commandOp].as<std::string>();
    const auto commandIter = commandMapping_.find(commandName);
    if (commandIter == commandMapping_.end()) {
        throw std::invalid_argument(std::format("Unknown command name ''", commandName));
    }
    // @note: check out and pass option only for 'enc' and 'dec' commands
    if (commandName == CommandTypeStr::encCom || commandName == CommandTypeStr::decCom) {
        if (!vm.count(outputOp)) {
            throw po::required_option(outputOp);
        }
        if (!vm.count(passwordOp)) {
            throw po::required_option(passwordOp);
        }
    }
    command_ = commandIter->second;
    inputFile_ = vm[inputOp].as<std::string>();
    outputFile_ = vm.count(outputOp) ? vm[outputOp].as<std::string>() : std::string{};
    password_ = vm.count(passwordOp) ? vm[passwordOp].as<std::string>() : std::string{};
}

}  // namespace CryptoGuard
