#include "cmd_options.h"
#include <exception>
#include <gtest/gtest.h>

using namespace CryptoGuard;

TEST(ProgramOptions, EncryptCommandGood) {
    CryptoGuard::ProgramOptions po;
    std::array<const char *, 9> argv{"CryptoGuard", "--input", "in.txt",    "--output", "out.txt",
                                     "--password",  "123",     "--command", "encrypt"};
    po.Parse(argv.size(), const_cast<char **>(argv.data()));
    CryptoGuard::ProgramOptions::COMMAND_TYPE command = po.GetCommand();

    std::string inFile = po.GetInputFile();
    std::string outFile = po.GetOutputFile();
    std::string password = po.GetPassword();

    EXPECT_TRUE(inFile == "in.txt");
    EXPECT_TRUE(outFile == "out.txt");
    EXPECT_TRUE(password == "123");
    EXPECT_TRUE(command == CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
}

TEST(ProgramOptions, EncryptCommandShortGood) {
    CryptoGuard::ProgramOptions po;
    std::array<const char *, 9> argv{"CryptoGuard", "-i", "in.txt", "-o", "out.txt", "-p", "123", "-c", "encrypt"};
    po.Parse(argv.size(), const_cast<char **>(argv.data()));
    CryptoGuard::ProgramOptions::COMMAND_TYPE command = po.GetCommand();

    std::string inFile = po.GetInputFile();
    std::string outFile = po.GetOutputFile();
    std::string password = po.GetPassword();

    EXPECT_TRUE(inFile == "in.txt");
    EXPECT_TRUE(outFile == "out.txt");
    EXPECT_TRUE(password == "123");
    EXPECT_TRUE(command == CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
}

TEST(ProgramOptions, UnknownCommand) {
    CryptoGuard::ProgramOptions po;
    std::array<const char *, 9> argv{"CryptoGuard", "-i", "in.txt", "-o", "out.txt", "-p", "123", "-c", "run"};
    po.Parse(argv.size(), const_cast<char **>(argv.data()));
    CryptoGuard::ProgramOptions::COMMAND_TYPE command = po.GetCommand();

    EXPECT_TRUE(command == CryptoGuard::ProgramOptions::COMMAND_TYPE::UNKNOWN);
}

TEST(ProgramOptions, WrongArgName) {
    CryptoGuard::ProgramOptions po;
    std::array<const char *, 9> argv{"CryptoGuard", "--input", "in.txt", "--output", "out.txt",
                                     "--pass",      "123",     "--run",  "encrypt"};

    ASSERT_THROW(po.Parse(argv.size(), const_cast<char **>(argv.data())), std::exception);
}

TEST(ProgramOptions, NoInputFile) {
    CryptoGuard::ProgramOptions po;
    std::array<const char *, 9> argv{"CryptoGuard", "--output", "out.txt", "--pass", "123", "--command", "encrypt"};

    ASSERT_THROW(po.Parse(argv.size(), const_cast<char **>(argv.data())), std::exception);
}

TEST(ProgramOptions, NoPassword) {
    CryptoGuard::ProgramOptions po;
    std::array<const char *, 9> argv{"CryptoGuard", "--input", "in.txt", "--output", "out.txt", "--command", "decrypt"};

    ASSERT_THROW(po.Parse(argv.size(), const_cast<char **>(argv.data())), std::exception);
}