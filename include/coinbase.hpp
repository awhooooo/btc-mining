#ifndef MINER_COINBASE_H
#define MINER_COINBASE_H

#include "include/types.hpp"

#include <bitcoin/system.hpp>

using namespace libbitcoin;
using namespace libbitcoin::wallet;
using namespace libbitcoin::chain;
using namespace libbitcoin::machine;

enum ADDRESS_TYPE
{
    LEGACY = 0,
    P2SH = 1,
    WITNESS_V0 = 2,
    WITNESS_V1 = 3,
    INVALID = 4,
};

void ConstructCoinbaseTx(const blocktemplate_t& blocktemplate, const std::pair<ADDRESS_TYPE, std::string>& coinbase_addr, transaction* tx);
byte_array<SHA256_OUTPUT_SIZE> GetTxid(const transaction* tx);

ADDRESS_TYPE CheckAddressFormat(const std::string& addr);
std::vector<uint8_t> ToMinimalLittleEndian(unsigned int value);

template <typename T>
T GenerateNonce()
{
    static_assert(std::is_unsigned<T>::value, "GenerateNonce only works with unsigned types");
    uint64_t random_number = pseudo_random();

    // Handle different return types
    if constexpr (std::is_same<T, uint64_t>::value) {
        return random_number;  // Return the full 64-bit random number
    } 
    else if constexpr (std::is_same<T, uint32_t>::value) {
        return static_cast<uint32_t>(random_number % UINT32_MAX);  // Return remainder for uint32_t
    } 
    else if constexpr (std::is_same<T, uint8_t>::value) {
        return static_cast<uint8_t>(random_number % UINT8_MAX);  // Return remainder for uint8_t
    } 
    else {
        static_assert(sizeof(T) <= 8, "Unsupported nonce type");
        return static_cast<T>(random_number);  // Default to casting for any other unsigned type
    }
}

#endif




