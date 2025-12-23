#include "cmd_options.h"
#include <boost/program_options/cmdline.hpp>
#include <boost/program_options/value_semantic.hpp>
#include <iostream>
#include <print>
#include <stdexcept>
#include <string>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()("help,h", "Print this help");
    desc_.add_options()("input,i", po::value<std::string>(&inputFile_), "Input file");
    desc_.add_options()("output,o", po::value<std::string>(&outputFile_), "Output file");
    desc_.add_options()("password,p", po::value<std::string>(&password_), "Password");
    desc_.add_options()("command,c", po::value<std::string>(), "Command: encrypt | decrypt | checksum");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    try {
        po::command_line_style::style_t style = po::command_line_style::style_t(
            po::command_line_style::unix_style | po::command_line_style::case_insensitive);
        po::store(po::parse_command_line(argc, argv, desc_, style), vm_);
        po::notify(vm_);

        if (vm_.count("help")) {
            std::cout << desc_ << std::endl;
            throw std::runtime_error{"Help message"};
        }

        if (!vm_.count("input")) {
            throw(std::runtime_error{"Specify input file"});
        }

        command_ = MapCmdStrToCmdType(vm_.at("command").as<std::string>());

        if ((command_ == COMMAND_TYPE::ENCRYPT || command_ == COMMAND_TYPE::DECRYPT) &&
            (!vm_.count("password") || !vm_.count("output"))) {
            std::cout << desc_ << std::endl;
            throw std::runtime_error{"Specify output file and password"};
        }

    } catch (const po::error &ex) {
        std::print(std::cerr, "Arg error: {}. See --help\n", ex.what());
        throw;
    }
}

ProgramOptions::COMMAND_TYPE ProgramOptions::MapCmdStrToCmdType(const std::string &cmd) const {

    if (cmd.empty()) {
        return ProgramOptions::COMMAND_TYPE::NONE;
    }

    if (commandMapping_.contains(cmd)) {
        return commandMapping_.at(cmd);
    }

    return ProgramOptions::COMMAND_TYPE::UNKNOWN;
}

}  // namespace CryptoGuard
