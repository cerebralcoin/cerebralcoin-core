#!/usr/bin/env bash

export LC_ALL=C
TOPDIR=${TOPDIR:-$(git rev-parse --show-toplevel)}
BUILDDIR=${BUILDDIR:-$TOPDIR}

BINDIR=${BINDIR:-$BUILDDIR/src}
MANDIR=${MANDIR:-$TOPDIR/doc/man}

CEREBRALCOIND=${CEREBRALCOIND:-$BINDIR/cerebralcoind}
CEREBRALCOINCLI=${CEREBRALCOINCLI:-$BINDIR/cerebralcoin-cli}
CEREBRALCOINTX=${CEREBRALCOINTX:-$BINDIR/cerebralcoin-tx}
WALLET_TOOL=${WALLET_TOOL:-$BINDIR/cerebralcoin-wallet}
CEREBRALCOINQT=${CEREBRALCOINQT:-$BINDIR/qt/cerebralcoin-qt}

[ ! -x $CEREBRALCOIND ] && echo "$CEREBRALCOIND not found or not executable." && exit 1

# The autodetected version git tag can screw up manpage output a little bit
CEBVER=($($CEREBRALCOINCLI --version | head -n1 | awk -F'[ -]' '{ print $6, $7 }'))

# Create a footer file with copyright content.
# This gets autodetected fine for cerebralcoind if --version-string is not set,
# but has different outcomes for cerebralcoin-qt and cerebralcoin-cli.
echo "[COPYRIGHT]" > footer.h2m
$CEREBRALCOIND --version | sed -n '1!p' >> footer.h2m

for cmd in $CEREBRALCOIND $CEREBRALCOINCLI $CEREBRALCOINTX $WALLET_TOOL $CEREBRALCOINQT; do
  cmdname="${cmd##*/}"
  help2man -N --version-string=${CEBVER[0]} --include=footer.h2m -o ${MANDIR}/${cmdname}.1 ${cmd}
  sed -i "s/\\\-${CEBVER[1]}//g" ${MANDIR}/${cmdname}.1
done

rm -f footer.h2m
