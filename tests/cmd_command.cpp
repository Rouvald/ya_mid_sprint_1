#include "boost/program_options/errors.hpp"
#include "cmd_options.h"
#include <gtest/gtest.h>
#include <stdexcept>
#include <vector>

using comType = CryptoGuard::ProgramOptions::COMMAND_TYPE;

struct ProgramOptionsCheckGetters {
    comType command{comType::MAX};
    std::string inputFile;
    std::string outputFile;
    std::string password;
};

namespace {
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

constexpr auto errorCommand{"someErrorCommand"};
};  // namespace

std::vector<char *> GetCharVec(const std::vector<std::string> &ops) {
    std::vector<char *> vec;
    vec.reserve(ops.size() + 1);
    vec.push_back(const_cast<char *>("/path/to/app"));  // @note: needed
    for (auto &val : ops) {
        vec.push_back(const_cast<char *>(val.data()));
    }
    return vec;
}

// i need copy of 'ops' to use 'char*', not 'const char*'
void CheckParseWithOps(std::vector<std::string> ops, const ProgramOptionsCheckGetters &res) {

    auto vec = GetCharVec(ops);

    CryptoGuard::ProgramOptions options;
    options.Parse(vec.size(), vec.data());

    EXPECT_EQ(options.GetCommand(), res.command);
    EXPECT_EQ(options.GetInputFile(), res.inputFile);
    EXPECT_EQ(options.GetOutputFile(), res.outputFile);
    EXPECT_EQ(options.GetPassword(), res.password);
};

TEST(ProgramOptionsTest, CtorTest) {
    CryptoGuard::ProgramOptions options;
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::MAX);
    EXPECT_TRUE(options.GetInputFile().empty());
    EXPECT_TRUE(options.GetOutputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());
}

TEST(ProgramOptionsTest, ParseHelpTest) {
    CheckParseWithOps({helpOp}, {
                                    comType::MAX,
                                    "",
                                    "",
                                    "",
                                });
    CheckParseWithOps({helpOpShort}, {comType::MAX, "", "", ""});
}

TEST(ProgramOptionsTest, ParseCommandEncryptTest) {
    CheckParseWithOps(
        {
            commandOp,                            //
            CryptoGuard::CommandTypeStr::encCom,  //
            inputOp,                              //
            inputFile,                            //
            outputOp,                             //
            outputFile,                           //
            passwordOp,                           //
            password                              //
        },
        {
            comType::ENCRYPT,  //
            inputFile,         //
            outputFile,        //
            password           //
        });
    CheckParseWithOps(
        {
            commandOpShort,                       //
            CryptoGuard::CommandTypeStr::encCom,  //
            inputOpShort,                         //
            inputFile,                            //
            outputOp,                             //
            outputFile,                           //
            passwordOp,                           //
            password                              //
        },
        {
            comType::ENCRYPT,  //
            inputFile,         //
            outputFile,        //
            password           //
        });
}
TEST(ProgramOptionsTest, ParseCommandDecryptTest) {
    CheckParseWithOps(
        {
            commandOp,                            //
            CryptoGuard::CommandTypeStr::decCom,  //
            inputOp,                              //
            inputFile,                            //
            outputOp,                             //
            outputFile,                           //
            passwordOp,                           //
            password                              //
        },
        {
            comType::DECRYPT,  //
            inputFile,         //
            outputFile,        //
            password           //
        });
    CheckParseWithOps(
        {
            commandOpShort,                       //
            CryptoGuard::CommandTypeStr::decCom,  //
            inputOpShort,                         //
            inputFile,                            //
            outputOp,                             //
            outputFile,                           //
            passwordOp,                           //
            password                              //
        },
        {
            comType::DECRYPT,  //
            inputFile,         //
            outputFile,        //
            password           //
        });
}
TEST(ProgramOptionsTest, ParseCommandChecksumTest) {
    CheckParseWithOps(
        {
            commandOp,                              //
            CryptoGuard::CommandTypeStr::checkCom,  //
            inputOp,                                //
            inputFile                               //
        },
        {
            comType::CHECKSUM,  //
            inputFile,          //
            "",                 //
            ""                  //
        });
    CheckParseWithOps(
        {
            commandOpShort,                         //
            CryptoGuard::CommandTypeStr::checkCom,  //
            inputOpShort,                           //
            inputFile,                              //
        },
        {
            comType::CHECKSUM,  //
            inputFile,          //
            "",                 //
            ""                  //
        });
}

TEST(ProgramOptionsTest, ErrorArgvParseTest) {
    // @note: without command name
    {
        std::vector<std::string> ops{commandOpShort};
        auto vec = GetCharVec(ops);

        CryptoGuard::ProgramOptions options;
        ASSERT_THROW(options.Parse(vec.size(), vec.data()), CryptoGuard::po::invalid_command_line_syntax);
    }
    // @note: without input op
    {
        std::vector<std::string> ops{commandOpShort, errorCommand};
        auto vec = GetCharVec(ops);

        CryptoGuard::ProgramOptions options;
        ASSERT_THROW(options.Parse(vec.size(), vec.data()), CryptoGuard::po::required_option);
    }
    // @note: without input file name
    {
        std::vector<std::string> ops{commandOpShort, CryptoGuard::CommandTypeStr::encCom, inputOpShort};
        auto vec = GetCharVec(ops);

        CryptoGuard::ProgramOptions options;
        ASSERT_THROW(options.Parse(vec.size(), vec.data()), CryptoGuard::po::invalid_command_line_syntax);
    }
    // @note: without output op (needed for encrypt command)
    {
        std::vector<std::string> ops{commandOpShort, CryptoGuard::CommandTypeStr::encCom, inputOpShort, inputFile};
        auto vec = GetCharVec(ops);

        CryptoGuard::ProgramOptions options;
        ASSERT_THROW(options.Parse(vec.size(), vec.data()), CryptoGuard::po::required_option);
    }
    // @note: without password op (needed for encrypt command)
    {
        std::vector<std::string> ops{
            commandOpShort, CryptoGuard::CommandTypeStr::encCom, inputOpShort, inputFile, outputOpShort, outputFile};
        auto vec = GetCharVec(ops);

        CryptoGuard::ProgramOptions options;
        ASSERT_THROW(options.Parse(vec.size(), vec.data()), CryptoGuard::po::required_option);
    }
    // @note: app call without ops
    {
        std::vector<std::string> ops{""};
        auto vec = GetCharVec(ops);

        CryptoGuard::ProgramOptions options;
        ASSERT_THROW(options.Parse(vec.size(), vec.data()), std::runtime_error);
    }
    // @note: app call with string
    {
        std::vector<std::string> ops{"error"};
        auto vec = GetCharVec(ops);

        CryptoGuard::ProgramOptions options;
        ASSERT_THROW(options.Parse(vec.size(), vec.data()), std::runtime_error);
    }
    // @note: app call with unregistered op
    {
        std::vector<std::string> ops{"--error"};
        auto vec = GetCharVec(ops);

        CryptoGuard::ProgramOptions options;
        ASSERT_THROW(options.Parse(vec.size(), vec.data()), CryptoGuard::po::unknown_option);
    }
}