#include "include/arguments.hpp"

#include <iostream>

namespace po = boost::program_options;

ArgsOptions args_parser(int argc, char* argv[])
{
    ArgsOptions miner_option;
    try {
        po::options_description opdesc("Allowed Options");
        opdesc.add_options()
            ("help,h", "Display this help message and exit")
            ("username,u", po::value<std::string>()->required(), "Set Bitcoin Core RPC server username")
            ("password,p", po::value<std::string>()->required(), "Set Bitcoin Core RPC server password")
            ("coinbase_addr,c", po::value<std::string>()->required(), "Set coinbase address to receive mined coins: P2TR addresses are not recommended")
            ("address,a", po::value<std::string>()->required(), "Set Bitcoin Core RPC server address")
            ("port,P", po::value<int>()->required(), "Set Bitcoin Core RPC server port number")
            ("threads,t", po::value<int>()->required(), "Set the number of threads")
            ("debug,d", po::bool_switch()->default_value(false), "Set the debug logging option");
            
        // Store and parse command-line arguments
        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, opdesc), vm);

        if (vm.count("help")) {
            std::cout << opdesc << "\n";
            exit(EXIT_SUCCESS);
        }

        po::notify(vm);

        miner_option.username = vm["username"].as<std::string>();
        miner_option.password = vm["password"].as<std::string>();
        miner_option.coinbase_addr = vm["coinbase_addr"].as<std::string>();
        miner_option.RPC_address = vm["address"].as<std::string>();
        miner_option.RPC_port = vm["port"].as<int>();
        miner_option.threads = vm["threads"].as<int>();
        miner_option.debug = vm["debug"].as<bool>();
    }
    catch (const po::error &ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        // spdlog::error("{}", ex.what());
        exit(EXIT_FAILURE);
    }
    return miner_option;
}