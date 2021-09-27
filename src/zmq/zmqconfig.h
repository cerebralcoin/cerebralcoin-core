// Copyright (c) 2009-2019 The Bitcoin Core developers 
// Copyright (c) 2019-2021 The Cerebral Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CEREBRALCOIN_ZMQ_ZMQCONFIG_H
#define CEREBRALCOIN_ZMQ_ZMQCONFIG_H

#if defined(HAVE_CONFIG_H)
#include <config/cerebralcoin-config.h>
#endif

#include <stdarg.h>
#include <string>

#if ENABLE_ZMQ
#include <zmq.h>
#endif

#include <primitives/block.h>
#include <primitives/transaction.h>

void zmqError(const char *str);

#endif // CEREBRALCOIN_ZMQ_ZMQCONFIG_H
