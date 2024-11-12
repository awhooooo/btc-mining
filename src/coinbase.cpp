#include "include/coinbase.hpp"
#include "include/bech32.hpp"
#include "include/segwit_addr.hpp"

#include <spdlog/spdlog.h>

#include <random>

void ConstructCoinbaseTx(const blocktemplate_t& blocktemplate, const std::pair<ADDRESS_TYPE, std::string>& coinbase_address, transaction* tx)
{
    hash_digest prev_txid1;
    decode_base16(prev_txid1, "0000000000000000000000000000000000000000000000000000000000000000");
    uint32_t input_index1 = 0xffffffff;
	output_point vin1(prev_txid1, input_index1);
	
	//make Input
	input input1 = input();
	input1.set_previous_output(vin1);
	input1.set_sequence(0xffffffff);

    uint64_t output_value1 = blocktemplate.coinbasevalue;

    script output_script1;
    assert(coinbase_address.first != ADDRESS_TYPE::INVALID);
    if ((coinbase_address.first == ADDRESS_TYPE::LEGACY)) {
        wallet::payment_address mining_address(coinbase_address.second);
        output_script1 = script().to_pay_key_hash_pattern(mining_address.hash());
    }

    if ((coinbase_address.first == ADDRESS_TYPE::P2SH)) {
        wallet::payment_address mining_address(coinbase_address.second);
        output_script1 = script().to_pay_script_hash_pattern(mining_address.hash());
    }

    if ((coinbase_address.first == ADDRESS_TYPE::WITNESS_V0)) {
        std::vector<uint8_t> witnessprogram;
        witnessprogram.reserve(32);
        witnessprogram = segwit_addr::decode("bc", coinbase_address.second).second;
        output_script1 = script({operation(opcode(0)), operation(to_chunk(witnessprogram))});
    }

    if ((coinbase_address.first == ADDRESS_TYPE::WITNESS_V1)) {
        std::vector<uint8_t> witnessprogram;
        witnessprogram.reserve(32);
        witnessprogram = segwit_addr::decode("bc", coinbase_address.second).second;
        output_script1 = script({operation(opcode(1)), operation(to_chunk(witnessprogram))});
    }
	output output1(output_value1, output_script1);

    uint64_t output_value2 = 0;
    std::string string_witness_commitment = blocktemplate.default_witness_commitment;
    data_chunk witness_commitment;
    decode_base16(witness_commitment, string_witness_commitment.erase(0, 4));
    script output_script2 = script().to_null_data_pattern(witness_commitment);
    output output2(output_value2, output_script2);

    (*tx).set_version(1);
    (*tx).set_locktime(0);

    (*tx).inputs().clear();
    (*tx).outputs().clear();
    (*tx).inputs().reserve(1);
    (*tx).outputs().reserve(2);

    (*tx).inputs().push_back(input1);
    (*tx).outputs().push_back(output1);
    (*tx).outputs().push_back(output2);

    /** BIP34 rule */
    std::vector<uint8_t> scriptSig;
    std::vector<uint8_t> cb_height = ToMinimalLittleEndian(blocktemplate.height);
    int cb_height_length = cb_height.size();
    scriptSig.push_back(static_cast<uint8_t>(cb_height_length));
    scriptSig.insert(scriptSig.end(), cb_height.begin(), cb_height.end());

    /** Appending 4 uint64_t pseudorandom numbers */
    for (int i = 0; i < 4; i++) {
        byte_array<8> extranonce = to_little_endian<uint64_t>(pseudo_random());
        scriptSig.insert(scriptSig.end(), extranonce.begin(), extranonce.end());
    }
    script coinbase_scriptSig = script(to_chunk(scriptSig), false);

    hash_digest sig1;
    decode_base16(sig1, "0000000000000000000000000000000000000000000000000000000000000000");
    data_stack witness1; 
	witness1.push_back(to_chunk(sig1));
	witness txinwitness1(witness1);

    (*tx).inputs()[0].set_script(coinbase_scriptSig);
    (*tx).inputs()[0].set_witness(txinwitness1);
}

byte_array<SHA256_OUTPUT_SIZE> GetTxid(const transaction* tx)
{
    byte_array<SHA256_OUTPUT_SIZE> hash = (*tx).hash();
    std::reverse(hash.begin(), hash.end());
    return hash;
}

ADDRESS_TYPE CheckAddressFormat(const std::string& addr)
{
    byte_array<25> decoded;
    if (decode_base58(decoded, addr)) {
        if (decoded[0] == 0x00) {
            spdlog::info("Mining Address: {} (Legacy)", addr);
            return ADDRESS_TYPE::LEGACY;
        }
        if (decoded[0] == 0x05) {
            spdlog::info("Mining Address: {} (Pay to ScriptHash)", addr);
            return ADDRESS_TYPE::P2SH;
        }
    }
    
    int segwit_decode_result = segwit_addr::decode("bc", addr).first;
    if (segwit_decode_result == 0) {
        spdlog::info("Mining Address: {} (Native Segwit)", addr);
        return ADDRESS_TYPE::WITNESS_V0;
    }
    if (segwit_decode_result == 1) {
        spdlog::info("Mining Address: {} (Taproot)", addr);
        return ADDRESS_TYPE::WITNESS_V1;
    }

    /** Base58 or Bech32 decode both failed */
    spdlog::info("Mining Address: {} (Invalid or Unknown Format)", addr);
    return ADDRESS_TYPE::INVALID;
}

std::vector<uint8_t> ToMinimalLittleEndian(unsigned int value) {
    std::vector<uint8_t> result;
    while (value > 0) {
        result.push_back(static_cast<uint8_t>(value & 0xff)); // Extract the least significant byte
        value >>= 8; // Shift the integer right by 8 bits to get the next byte
    }
    return result;
}
