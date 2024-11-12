#include "include/calculation.hpp"

#include <cassert>
#include <sstream>
#include <iomanip>

void CBlockHeaderCalculation::Init(const std::string& coinbase_addr)
{
    /** No race condition in Initialization */

    this->found.store(false);
    this->shutdown_flag.store(false);
    this->SetCoinbaseAddr(coinbase_addr);

    try {
        this->current_block_template = this->RPC->getblocktemplate();
        ConstructCoinbaseTx(this->current_block_template, this->coinbase_address, &this->coinbase_tx);

        this->version = to_little_endian<uint32_t>(this->current_block_template.version);
        decode_base16(this->prevhash, this->current_block_template.previousblockhash);

        decode_base16(this->nbits, this->current_block_template.bits);
        this->time = to_little_endian<uint32_t>(this->current_block_template.curtime);

        decode_base16(this->targethash, this->current_block_template.target);
        spdlog::debug("getblocktemplate Done");
    } 
    catch (CBitcoinException error) {
        spdlog::critical("Connection Error: {}. Terminating Program.", error.getMessage());
        exit(EXIT_FAILURE);
    }

    // spdlog::info("{}", encode_base16(this->CalculateWitnessCommitment()));
    // spdlog::info("{}", this->current_block_template.default_witness_commitment);
    // if (encode_base16(this->CalculateWitnessCommitment()) != this->current_block_template.default_witness_commitment) {
    //     exit(EXIT_FAILURE);
    // }

    this->block_ready.store(true);
    this->attempts.store(0);
    spdlog::debug("Initiation Done");
}

byte_array<BLOCK_HEADER_SIZE> CBlockHeaderCalculation::MakeNextBlockHeader()
{
    byte_array<NONCE_SIZE> nonce = to_little_endian<uint32_t>(GenerateNonce<uint32_t>());

    assert(this->version.size() + this->prevhash.size() + this->merkleroot.size() + 
           this->time.size() + this->nbits.size() + nonce.size() == BLOCK_HEADER_SIZE);
    byte_array<BLOCK_HEADER_SIZE> block_header;

    /** 
     * hashPrevBlock, hashMerkleRoot and nBits in internal byte order
     * nVersion, nTime and nNonce in reverse byte order
     */

    size_t offset = 0;
    std::copy(this->version.begin(), this->version.end(), block_header.begin() + offset);
    offset += VERSION_SIZE;

    std::copy(this->prevhash.rbegin(), this->prevhash.rend(), block_header.begin() + offset);
    offset += SHA256_OUTPUT_SIZE;

    std::copy(this->merkleroot.rbegin(), this->merkleroot.rend(), block_header.begin() + offset);
    offset += SHA256_OUTPUT_SIZE;

    std::copy(this->time.begin(), this->time.end(), block_header.begin() + offset);
    offset += TIME_SIZE;

    std::copy(this->nbits.rbegin(), this->nbits.rend(), block_header.begin() + offset);
    offset += NBITS_SIZE;

    std::copy(nonce.begin(), nonce.end(), block_header.begin() + offset);
    offset += NONCE_SIZE;
    assert(offset == BLOCK_HEADER_SIZE);

    return block_header;
}

byte_array<SHA256_OUTPUT_SIZE> CBlockHeaderCalculation::GetNextBlockHash(const byte_array<BLOCK_HEADER_SIZE>& blockheader) const
{
    byte_array<SHA256_OUTPUT_SIZE> result = sha256_hash(sha256_hash_chunk(blockheader));
    std::reverse(result.begin(), result.end());
    return result;
}

void CBlockHeaderCalculation::SetCoinbaseAddr(const std::string& coinbase_addr)
{
    ADDRESS_TYPE addr_type = CheckAddressFormat(coinbase_addr);
    if (addr_type == ADDRESS_TYPE::INVALID) {
        spdlog::critical("Error: Wrong CoinBase Address Input. Terminating Program");
        exit(EXIT_FAILURE);
    }
    this->coinbase_address = std::make_pair(addr_type, coinbase_addr);
}

bool CBlockHeaderCalculation::IsFound() const
{
    return this->found.load(std::memory_order_acquire);
}

void CBlockHeaderCalculation::SetFoundTrue()
{
    this->found.store(true, std::memory_order_release);
}

void CBlockHeaderCalculation::SetFoundFalse()
{
    this->found.store(false, std::memory_order_release);
}

void CBlockHeaderCalculation::Shutdown()
{
    this->shutdown_flag.store(true, std::memory_order_release);
}

bool CBlockHeaderCalculation::IsShutdown() const
{
    return this->shutdown_flag.load(std::memory_order_acquire);
}

void CBlockHeaderCalculation::Update()
{
    /** Ensures only this thread is altering the block template */
    std::lock_guard<std::mutex> lock(this->mtx);
    this->block_ready.store(false, std::memory_order_relaxed);

    /** get a new block template */
    try {
        blocktemplate_t new_block_template = this->RPC->getblocktemplate();
        this->current_block_template = new_block_template;
        ConstructCoinbaseTx(this->current_block_template, this->coinbase_address, &this->coinbase_tx);

        this->version = to_little_endian<uint32_t>(this->current_block_template.version);
        decode_base16(this->prevhash, this->current_block_template.previousblockhash);

        decode_base16(this->nbits, this->current_block_template.bits);
        this->time = to_little_endian<uint32_t>(this->current_block_template.curtime);

        decode_base16(this->targethash, this->current_block_template.target);
    }
    catch (CBitcoinException error) {
        spdlog::critical("Connection Error: {}. Terminating Program.", error.getMessage());
        exit(EXIT_FAILURE);
    }

    /** Let other threads be informed that change is complete */
    this->block_ready.store(true, std::memory_order_release);
    this->cv.notify_all();
    spdlog::debug("Block Template Updated");
}

void CBlockHeaderCalculation::SetMerkleRoot()
{
    std::vector<std::string> txvec;
    byte_array<SHA256_OUTPUT_SIZE> coinbase_txid = this->coinbase_tx.hash();
    std::reverse(coinbase_txid.begin(), coinbase_txid.end());
    txvec.push_back(encode_base16(coinbase_txid));

    for (const auto& tx_json : this->current_block_template.transactions) {
        txvec.push_back(tx_json["txid"].asString());
    }

    this->merkleroot = this->CalculateMerkleRoot(txvec);
    // std::reverse(this->merkleroot.begin(), this->merkleroot.end());
}

byte_array<SHA256_OUTPUT_SIZE> CBlockHeaderCalculation::CalculateMerkleRoot(std::vector<byte_array<SHA256_OUTPUT_SIZE>>& txlist)
{
    if (txlist.empty()) {
        return null_hash;
    }

    while (txlist.size() > 1) {
        if (txlist.size() % 2 == 1) {
            txlist.push_back(txlist.back());
        }

        std::vector<hash_digest> newtxidlist;
        newtxidlist.reserve(txlist.size() / 2 + 1);

        for (size_t i = 0; i < txlist.size(); i += 2) {
            // Concatenate two adjacent hashes and hash them together
            newtxidlist.push_back(sha256_hash(sha256_hash(txlist[i], txlist[i + 1])));
        }
        std::swap(txlist, newtxidlist);
    }

    assert(txlist.size() == 1);
    std::reverse(txlist[0].begin(), txlist[0].end());
    return txlist[0];
}

byte_array<SHA256_OUTPUT_SIZE> CBlockHeaderCalculation::CalculateMerkleRoot(const std::vector<std::string>& txlist)
{
    std::vector<byte_array<SHA256_OUTPUT_SIZE>> txlistbytes;
    txlistbytes.reserve(txlist.size() + 1);
    
    for (const auto& tx : txlist) {
        byte_array<SHA256_OUTPUT_SIZE> txid;
        decode_base16(txid, tx);
        std::reverse(txid.begin(), txid.end());
        txlistbytes.push_back(txid);
    }

    return CalculateMerkleRoot(txlistbytes);
}

data_chunk CBlockHeaderCalculation::CalculateWitnessCommitment()
{
    std::vector<chain::transaction> vTx;
    vTx.reserve(this->current_block_template.transactions.size() + 1);

    for (const auto& tx_json : this->current_block_template.transactions) {
        data_chunk raw_tx_bytes;
        decode_base16(raw_tx_bytes, tx_json["data"].asString());

        chain::transaction tx;
        tx.from_data(raw_tx_bytes, true);
        vTx.emplace_back(tx);
    }

    std::vector<byte_array<SHA256_OUTPUT_SIZE>> witness_hashes;
    witness_hashes.reserve(this->current_block_template.transactions.size() + 1);
    witness_hashes[0] = null_hash;
    for (const chain::transaction& tx : vTx) {
        witness_hashes.push_back(tx.hash(/*witness=*/true));
    }

    byte_array<SHA256_OUTPUT_SIZE> witness_merkle_root = this->CalculateMerkleRoot(witness_hashes);
    byte_array<SHA256_OUTPUT_SIZE> commitment_hash = sha256_hash(sha256_hash(witness_merkle_root, null_hash));

    // Create the OP_RETURN script for the witness commitment
    data_chunk witness_commitment = {0xaa, 0x21, 0xa9, 0xed};
    witness_commitment.insert(witness_commitment.end(), commitment_hash.begin(), commitment_hash.end());
    chain::script witness_commitment_script = script().to_null_data_pattern(witness_commitment);
    // assert(witness_commitment_script.size() == WITNESS_COMMITMENT_SIZE);

    return witness_commitment_script.to_data(false);
}

std::string CBlockHeaderCalculation::MakeNextBlock(const byte_array<BLOCK_HEADER_SIZE>& blockheader, const transaction& coinbase_tx, const blocktemplate_t& blocktemplate)
{
    std::string result;
    std::stringstream ss;
    
    for (const auto& byte : blockheader) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }

    size_t nTx = 1 + blocktemplate.transactions.size();
    ss << std::hex << std::setw(2) << std::setfill('0') << nTx;
    result += ss.str();

    result += encode_base16(coinbase_tx.to_data(true, true));

    for (const auto& tx : blocktemplate.transactions) {
        result += tx["data"].asString();
    }
    spdlog::info(result);
    return result;
}

void CBlockHeaderCalculation::StartMining()
{
    this->startpoint = std::chrono::steady_clock::now();

    while (!this->IsFound() && !this->IsShutdown())  // Check shutdown condition in the inner loop
    {
        byte_array<BLOCK_HEADER_SIZE> nextblockheader = this->MakeNextBlockHeader();
        byte_array<SHA256_OUTPUT_SIZE> nextblockhash = this->GetNextBlockHash(nextblockheader);

        this->attempts++;

        /** Logs the number of attempts */
        if (attempts % 0x00fffffe == 0) {
            spdlog::info("Attempts Just Exceeded {} Times", this->attempts.load());
        }

        /** 
         * If all nonce possibilities are exhausted, try a new extra nonce
         */
        if (attempts % 0xffffffff == 0 && !this->IsFound()) {
            if (this->IsShutdown()) {
                break; // Exit early if shutdown is requested
            }
            spdlog::debug("Attempting Another ExtraNonce on CoinBase Transaction");
            this->Update();
            this->SetMerkleRoot();
        }

        /** Check if this thread has found a valid block hash */
        if (nextblockhash <= this->targethash && !this->IsFound()) 
        {
            // Atomically set the "found" flag so other threads stop mining this block
            this->SetFoundTrue();

            std::chrono::time_point<std::chrono::steady_clock> endpoint = std::chrono::steady_clock::now();
            std::chrono::duration<double> duration = endpoint - this->startpoint;

            spdlog::info("Block Hash Found:  {}", encode_base16(nextblockhash));
            spdlog::info("Target Difficulty: {}", encode_base16(this->targethash));
            spdlog::info("Attempts: {}", this->attempts.load());
            spdlog::info("Time Taken: {} Seconds", duration.count());

            /** 
             * Submit the block (Only one thread should submit the block) 
             * There is only one transaction in the block (Coinbase)
             */
            std::string nextblock = this->MakeNextBlock(nextblockheader, this->coinbase_tx, this->current_block_template);

            try {
                spdlog::debug("Submitting Block Header");
                std::string result = this->RPC->submitblock(nextblock);
                if (result.empty()) {
                    spdlog::info("Block Hash Accepted!");
                } 
                else {
                    spdlog::error("Block Validation Failed: {}", result);
                }                     
            } 
            catch (CBitcoinException error) {
                spdlog::critical("Connection Error: {}", error.getMessage());
                break;  // Exit if an exception occurs
            }

            /** Reset flag for the next block and update the block template */
            this->SetFoundFalse();  
            this->Update();
            this->SetMerkleRoot();
            break;
        }
    }

    /** Wait for the block template to be ready with a timeout */
    std::unique_lock<std::mutex> lock(this->mtx);
    this->cv.wait(lock, [this]() { return this->block_ready.load(std::memory_order_acquire); });
}
