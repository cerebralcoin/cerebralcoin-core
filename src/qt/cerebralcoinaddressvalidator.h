// Copyright (c) 2011-2014 The Cerebralcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CEREBRALCOIN_QT_CEREBRALCOINADDRESSVALIDATOR_H
#define CEREBRALCOIN_QT_CEREBRALCOINADDRESSVALIDATOR_H

#include <QValidator>

/** Base58 entry widget validator, checks for valid characters and
 * removes some whitespace.
 */
class CerebralcoinAddressEntryValidator : public QValidator
{
    Q_OBJECT

public:
    explicit CerebralcoinAddressEntryValidator(QObject *parent);

    State validate(QString &input, int &pos) const;
};

/** Cerebralcoin address widget validator, checks for a valid cerebralcoin address.
 */
class CerebralcoinAddressCheckValidator : public QValidator
{
    Q_OBJECT

public:
    explicit CerebralcoinAddressCheckValidator(QObject *parent);

    State validate(QString &input, int &pos) const;
};

#endif // CEREBRALCOIN_QT_CEREBRALCOINADDRESSVALIDATOR_H
