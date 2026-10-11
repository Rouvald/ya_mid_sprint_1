#include "cmd_options.h"
#include <array>
#include <gtest/gtest.h>
#include <optional>
#include <stdexcept>
#include <vector>

using comType = CryptoGuard::ProgramOptions::COMMAND_TYPE;

struct ProgramOptionsCheckGetters {
    comType command{comType::MAX};
    std::string inputFile;
    std::string outputFile;
    std::string password;
    std::optional<std::string> optionalRes;
};

std::vector<char *> GetCharVec(std::vector<std::string> &ops) {
    std::vector<char *> vec;
    vec.reserve(ops.size() + 1);
    vec.push_back("/path/to/app");  // @note: needed
    for (auto &val : ops) {
        vec.push_back(val.data());
    }
    return vec;
}

// i need copy of 'ops' to use 'char*', not 'const char*'
void CheckParseWithOps(std::vector<std::string> ops, const ProgramOptionsCheckGetters &res) {

    auto vec = GetCharVec(ops);

    CryptoGuard::ProgramOptions options;
    const auto parseRes = options.Parse(vec.size(), vec.data());

    EXPECT_EQ(parseRes, res.optionalRes);
    EXPECT_EQ(options.GetCommand(), res.command);
    EXPECT_EQ(options.GetInputFile(), res.inputFile);
    EXPECT_EQ(options.GetOutputFile(), res.outputFile);
    EXPECT_EQ(options.GetPassword(), res.password);
};

TEST(TestComponentName, CtorTest) {
    CryptoGuard::ProgramOptions options;
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::MAX);
    EXPECT_EQ(options.GetInputFile(), "");
    EXPECT_EQ(options.GetOutputFile(), "");
    EXPECT_EQ(options.GetPassword(), "");
}

TEST(TestComponentName, ParseTest) {

    constexpr auto helpOp{"--help"};
    constexpr auto helpOpShort{"-h"};
    constexpr auto commandOp{"--command"};
    constexpr auto commandOpShort{"-c"};
    constexpr auto inputOp{"--input"};
    constexpr auto inputOpShort{"-i"};
    constexpr auto outputOp{"--output"};
    constexpr auto outputOpShort{"-o"};
    constexpr auto passwordOp{"--password"};
    constexpr auto passwordOpShort{"-p"};

    // commands get from CryptoGuard::CommandTypeStr
    constexpr auto inputFile{"some_input.txt"};
    constexpr auto outputFile{"some_output.txt"};
    constexpr auto password{"someStrongPassword"};

    // help
    CheckParseWithOps({helpOp}, {comType::MAX, "", "", "", ""});
    CheckParseWithOps({helpOpShort}, {comType::MAX, "", "", "", ""});

    // commands
    CheckParseWithOps({commandOp, CryptoGuard::CommandTypeStr::encCom}, {comType::ENCRYPT});
    CheckParseWithOps({commandOp, CryptoGuard::CommandTypeStr::decCom}, {comType::DECRYPT});
    CheckParseWithOps({commandOp, CryptoGuard::CommandTypeStr::checkCom}, {comType::CHECKSUM});
    CheckParseWithOps({commandOpShort, CryptoGuard::CommandTypeStr::encCom}, {comType::ENCRYPT});
    CheckParseWithOps({commandOpShort, CryptoGuard::CommandTypeStr::decCom}, {comType::DECRYPT});
    CheckParseWithOps({commandOpShort, CryptoGuard::CommandTypeStr::checkCom}, {comType::CHECKSUM});

    // in out
    CheckParseWithOps({inputOp, inputFile}, {comType::MAX, inputFile});
    CheckParseWithOps({inputOpShort, inputFile}, {comType::MAX, inputFile});
    CheckParseWithOps({outputOp, outputFile}, {comType::MAX, "", outputFile});
    CheckParseWithOps({outputOpShort, outputFile}, {comType::MAX, "", outputFile});

    // pass
    CheckParseWithOps({passwordOp, password}, {comType::MAX, "", "", password});
    CheckParseWithOps({passwordOpShort, password}, {comType::MAX, "", "", password});

    // all
    CheckParseWithOps({commandOp, CryptoGuard::CommandTypeStr::encCom,  //
                       inputOp, inputFile,                              //
                       outputOp, outputFile,                            //
                       passwordOp, password},                           //
                      {comType::ENCRYPT, inputFile, outputFile, password});
}

TEST(TestComponentName, ErrorArgvParseTest) {
    CheckParseWithOps({""}, {comType::MAX, "", "", "", "App called without options!\n"});

    // @note: get this error, cos 'error' not a option, '--error' is option
    CheckParseWithOps({"error"}, {comType::MAX, "", "", "", "App called without options!\n"});

    // @note: test with error options -> raise boost throw
    std::vector<std::string> ops{"--error"};
    auto vec = GetCharVec(ops);

    CryptoGuard::ProgramOptions options;
    ASSERT_ANY_THROW(options.Parse(vec.size(), vec.data()));
}