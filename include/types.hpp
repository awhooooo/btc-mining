/**
 * @file    types.h
 * @author  Krzysztof Okupski
 * @date    29.10.2014
 * @version 1.0
 *
 * Type definitions for the JSON-RPC C++ interface.
 */

#ifndef MINER_TYPES_H
#define MINER_TYPES_H

#include <string>
#include <vector>

#include <json/json.h>

static const size_t WITNESS_COMMITMENT_SIZE = 38;
static const size_t BLOCK_HEADER_SIZE = 80;
static const size_t SHA256_OUTPUT_SIZE = 32;
static const size_t VERSION_SIZE = 4;
static const size_t NBITS_SIZE = 4;
static const size_t TIME_SIZE = 4;
static const size_t NONCE_SIZE = 4;

	/* === General types === */
	struct getblockchaininfo_t{
		int version;
		int protocolversion;
		int walletversion;
		double balance;
		int blocks;
		int timeoffset;
		int connections;
		std::string proxy;
		double difficulty;
		bool testnet;
		int keypoololdest;
		int keypoolsize;
		double paytxfee;
		int unlocked_until;
		std::string errors;
	};


	/* === Node types === */
	struct netaddress_t{
		std::string address;
		std::string connected;
	};

	struct nodeinfo_t{
		std::string addednode;
		bool connected;
		std::vector<netaddress_t> addresses;
	};

	struct peerinfo_t{
		std::string addr;
		std::string services;
		int lastsend;
		int lastrecv;
		int bytessent;
		int bytesrecv;
		int conntime;
		double pingtime;
		int version;
		std::string subver;
		bool inbound;
		int startingheight;
		int banscore;
	};


	/* === Account, address types === */
	struct accountinfo_t{
		std::string account;
		double amount;
		int confirmations;
	};

	struct addressinfo_t: accountinfo_t{
		std::string address;
		std::vector<std::string> txids;
	};

	struct transactioninfo_t: accountinfo_t{
		std::string address;
		std::string category;
		std::string blockhash;
		int blockindex;
		int blocktime;
		std::string txid;
		std::vector<std::string> walletconflicts;
		int time;
		int timereceived;
	};

	struct multisig_t{
		std::string address;
		std::string redeemScript;
	};

	struct validateaddress_t{
		bool isvalid;
		std::string address;
		bool ismine;
		bool isscript;
		std::string pubkey;
		bool iscompressed;
		std::string account;
	};

	struct addressgrouping_t{
		std::string address;
		double balance;
		std::string account;
	};

	/* === Transactions === */
	struct transactiondetails_t{
		std::string account;
		std::string address;
		std::string category;
		double amount;
		int vout;
		double fee;
	};

	struct gettransaction_t{
		double amount;
		double fee;
		int confirmations;
		std::string blockhash;
		int blockindex;
		int blocktime;
		std::string txid;
		std::vector<std::string> walletconflicts;
		int time;
		int timereceived;
		std::vector<transactiondetails_t> details;
		std::string hex;
	};

	struct decodescript_t{
		std::string assm;
		std::string type;
		std::string p2sh;

		int reqSigs;
		std::vector<std::string> addresses;
	};

	/* decoderawtransaction return type */
	struct scriptSig_t{
		std::string assm;
		std::string hex;
	};

	struct scriptPubKey_t{
		std::string assm;
		std::string hex;
		int reqSigs;
		std::string type;
		std::vector<std::string> addresses;
	};

	struct txout_t{
		std::string txid;
		unsigned int n;
	};

	struct vin_t: txout_t{
		scriptSig_t scriptSig;
		unsigned int sequence;
	};

	struct vout_t{
		double value;
		unsigned int n;
		scriptPubKey_t scriptPubKey;
	};

	struct decoderawtransaction_t{
		std::string txid;
		int version;
		int locktime;
		std::vector<vin_t> vin;
		std::vector<vout_t> vout;
	};



	/* getrawtransaction return type */
	struct getrawtransaction_t: decoderawtransaction_t{
		std::string hex;
		std::string blockhash;
		unsigned int confirmations;
		unsigned int time;
		unsigned int blocktime;
	};

	/* signrawtransaction return type */
	struct signrawtxin_t: txout_t{
		std::string scriptPubKey;
		std::string redeemScript;
	};

	/* signrawtransaction return type */
	struct signrawtransaction_t{
		std::string hex;
		bool complete;
	};





	/* === Other === */
	struct utxoinfo_t{
		std::string bestblock;
		int confirmations;
		double value;
		scriptPubKey_t scriptPubKey;
		int version;
		bool coinbase;
	};

	struct utxosetinfo_t{
		int height;
		std::string bestblock;
		int transactions;
		int txouts;
		int bytes_serialized;
		std::string hash_serialized;
		double total_amount;
	};

	struct unspenttxout_t: txout_t{
		std::string address;
		std::string account;
		std::string scriptPubKey;
		double amount;
		int confirmations;
	};


	/* === Unused yet === */
	struct blockinfo_t{
		std::string hash;
		int confirmations;
		int size;
		int height;
		int version;
		std::string merkleroot;
		std::vector<std::string> tx;
		unsigned int time;
		unsigned int nonce;
		std::string bits;
		double difficulty;
		std::string chainwork;
		std::string previousblockhash;
		std::string nextblockhash;
	};

	struct mininginfo_t{
		int blocks;
		int currentblocksize;
		int currentblocktx;
		double difficulty;
		std::string errors;
		int genproclimit;
		double networkhashps;
		int pooledtx;
		bool testnet;
		bool generate;
		int hashespersec;
	};

	struct blocktemplate_t{
		std::vector<std::string> capabilities;       	  // List of capabilities (e.g., "proposal")
		uint32_t version;                                 // Block version
		std::vector<std::string> rules;              	  // List of rules (e.g., "csv", "!segwit", "taproot")
		std::map<std::string, int> vbavailable;           // Version bits available (usually empty in basic template)
		int vbrequired;                                   // Version bits required
		std::string previousblockhash;                    // Previous block hash
		std::vector<Json::Value> transactions;       // List of transactions (simplified as a vector of strings)
		std::map<std::string, std::string> coinbaseaux;   // Auxiliary data for the coinbase transaction
		uint64_t coinbasevalue;                       	  // Value of the coinbase transaction in satoshis
		std::string longpollid;                      	  // Long polling ID
		std::string target;                          	  // Target value for the block
		uint64_t mintime;                                 // Minimum timestamp for the block
		std::vector<std::string> mutablefields;      	  // List of mutable fields (e.g., "time", "transactions", "prevblock")
		std::string noncerange;                      	  // Range of valid nonces
		int sigoplimit;                              	  // Limit on signature operations
		int sizelimit;                               	  // Limit on block size
		int weightlimit;                             	  // Limit on block weight
		uint64_t curtime;                              	  // Current time
		std::string bits;                            	  // Bits field in the block header
		int height;                                  	  // Height of the block being mined
		std::string default_witness_commitment;      	  // Default witness commitment, if any
	};

	struct workdata_t{
		std::string midstate;
		std::string data;
		std::string hash1;
		std::string target;
	};

	struct txsinceblock_t{
		std::vector<transactioninfo_t> transactions;
		std::string lastblock;
	};

#endif