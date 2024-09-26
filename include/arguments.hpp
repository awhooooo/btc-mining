#ifndef MINER_ARGUMENTS_H
#define MINER_ARGUMENTS_H

#include <boost/program_options.hpp>

struct ArgsOptions
{
    std::string username;
    std::string password;
    std::string coinbase_addr;
    std::string RPC_address;
    int RPC_port;
    int threads;
    bool debug;
};

ArgsOptions args_parser(int argc, char* argv[]);

#endif