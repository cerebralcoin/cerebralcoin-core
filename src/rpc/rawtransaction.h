// Copyright (c) 2009-2019 The Bitcoin Core developers 
// Copyright (c) 2019-2021 The Cerebral Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CEREBRALCOIN_RPC_RAWTRANSACTION_H
#define CEREBRALCOIN_RPC_RAWTRANSACTION_H

class CBasicKeyStore;
struct CMutableTransaction;
class UniValue;

namespace interfaces {
class Chain;
} // namespace interfaces

/** Sign a transaction with the given keystore and previous transactions */
UniValue SignTransaction(interfaces::Chain& chain, CMutableTransaction& mtx, const UniValue& prevTxs, CBasicKeyStore *keystore, bool tempKeystore, const UniValue& hashType);

/** Create a transaction from univalue parameters */
CMutableTransaction ConstructTransaction(const UniValue& inputs_in, const UniValue& outputs_in, const UniValue& locktime, bool rbf);

#endif // CEREBRALCOIN_RPC_RAWTRANSACTION_H
