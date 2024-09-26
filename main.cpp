#include "include/arguments.hpp"
#include "include/bitcoinrpc.hpp"
#include "include/calculation.hpp"

#include <random>
#include <thread>
#include <csignal>

/** Global pointer */
CBlockHeaderCalculation* pminer = nullptr;

void KeyboardInterruptHandler(int signal)
{
    if (signal == SIGINT && pminer != nullptr) {
        spdlog::info("Keyboard Interrupt Detected. Terminating Mining");
        pminer->Shutdown();
    }
}

int main(int argc, char* argv[])
{
    ArgsOptions args = args_parser(argc, argv);

    if (args.debug) {
        spdlog::set_level(spdlog::level::debug);
    }

    CBlockHeaderCalculation miner(args.username, args.password, args.coinbase_addr, args.RPC_address, args.RPC_port);
    pminer = &miner;

    /** 
    std::vector<std::future<void>> futures;
    futures.reserve(args.threads);

    for (int i = 0; i < args.threads; i++) {
        // Use std::async to launch the task asynchronously
        futures.emplace_back(std::async(std::launch::async, &CBlockHeaderCalculation::StartMining, &miner));
    }

    for (auto& fut : futures) {
        fut.get();
    }
    */

    std::signal(SIGINT, KeyboardInterruptHandler);  

    std::vector<std::thread> threads;
    threads.reserve(args.threads);

    for (int i = 0; i < args.threads; i++) {
        /** Use std::thread to launch the mining task */
        threads.emplace_back(&CBlockHeaderCalculation::StartMining, &miner);
    }

    for (auto& thread : threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    return EXIT_SUCCESS;
}