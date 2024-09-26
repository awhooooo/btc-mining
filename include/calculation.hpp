#ifndef MINER_CALCULATION_H
#define MINER_CALCULATION_H

#include "include/coinbase.hpp"
#include "include/bitcoinrpc.hpp"

#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <memory>
#include <random>

class CBlockHeaderCalculation
{
    private:
        std::unique_ptr<CBitcoinAPI> RPC;

        std::atomic<bool> shutdown_flag;
        std::atomic<bool> block_ready;
        std::atomic<bool> found;
        std::mutex mtx;
        std::condition_variable cv;

        blocktemplate_t current_block_template;
        byte_array<VERSION_SIZE> version;
        byte_array<SHA256_OUTPUT_SIZE> prevhash;
        byte_array<SHA256_OUTPUT_SIZE> merkleroot;
        byte_array<NBITS_SIZE> nbits;
        byte_array<TIME_SIZE> time;

        std::pair<ADDRESS_TYPE, std::string> coinbase_address;
        transaction coinbase_tx;
        byte_array<SHA256_OUTPUT_SIZE> targethash;

        std::atomic<uint64_t> attempts;
        std::chrono::time_point<std::chrono::steady_clock> startpoint;

        void Init(const std::string& coinbase_addr);
        void SetFoundTrue();
        void SetFoundFalse();

    public:
        explicit CBlockHeaderCalculation(const std::string& username, const std::string& password, const std::string& coinbase_addr, const std::string& address, const int port)
        : RPC(std::make_unique<CBitcoinAPI>(username, password, address, port))
        {
            this->Init(coinbase_addr);
            this->SetMerkleRoot();
        };

        CBlockHeaderCalculation(const CBlockHeaderCalculation& bhc) = delete;
        CBlockHeaderCalculation(CBlockHeaderCalculation&& bhc) = delete;

        ~CBlockHeaderCalculation() {};

        byte_array<BLOCK_HEADER_SIZE> MakeNextBlockHeader();
        byte_array<SHA256_OUTPUT_SIZE> GetNextBlockHash(const byte_array<BLOCK_HEADER_SIZE>& blockheader) const;

        void SetCoinbaseAddr(const std::string& coinbase_addr);
        bool IsFound() const;
        void Shutdown();
        bool IsShutdown() const;
        void Update();

        /**
         * We assume there is only one transaction (coinbase)
         * Improvement required for calculating the merkle hash of multiple transactions
         */
        void SetMerkleRoot();
        byte_array<SHA256_OUTPUT_SIZE> CalculateMerkleRoot(std::vector<byte_array<SHA256_OUTPUT_SIZE>>& txlist);
        byte_array<SHA256_OUTPUT_SIZE> CalculateMerkleRoot(const std::vector<std::string>& txlist);

        std::string MakeNextBlock(const byte_array<BLOCK_HEADER_SIZE>& blockheader, const transaction& coinbase_tx, const blocktemplate_t& blocktemplate);
        void StartMining();
};

#endif