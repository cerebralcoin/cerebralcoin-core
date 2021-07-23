Cerebralcoin Core
=============

Setup
---------------------
Cerebralcoin Core is the original Cerebralcoin client and it builds the backbone of the network. It downloads and, by default, stores the entire history of Cerebralcoin transactions, which requires a few hundred gigabytes of disk space. Depending on the speed of your computer and network connection, the synchronization process can take anywhere from a few hours to a day or more.

To download Cerebralcoin Core, visit [cerebralcoincore.org](https://cerebralcoincore.org/en/download/).

Running
---------------------
The following are some helpful notes on how to run Cerebralcoin Core on your native platform.

### Unix

Unpack the files into a directory and run:

- `bin/cerebralcoin-qt` (GUI) or
- `bin/cerebralcoind` (headless)

### Windows

Unpack the files into a directory, and then run cerebralcoin-qt.exe.

### macOS

Drag Cerebralcoin Core to your applications folder, and then run Cerebralcoin Core.

### Need Help?

* See the documentation at the [Cerebralcoin Wiki](https://en.cerebralcoin.it/wiki/Main_Page)
for help and more information.
* Ask for help on [#cerebralcoin](http://webchat.freenode.net?channels=cerebralcoin) on Freenode. If you don't have an IRC client, use [webchat here](http://webchat.freenode.net?channels=cerebralcoin).
* Ask for help on the [CerebralcoinTalk](https://cerebralcointalk.org/) forums, in the [Technical Support board](https://cerebralcointalk.org/index.php?board=4.0).

Building
---------------------
The following are developer notes on how to build Cerebralcoin Core on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [Dependencies](dependencies.md)
- [macOS Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [Windows Build Notes](build-windows.md)
- [FreeBSD Build Notes](build-freebsd.md)
- [OpenBSD Build Notes](build-openbsd.md)
- [NetBSD Build Notes](build-netbsd.md)
- [Gitian Building Guide (External Link)](https://github.com/cerebralcoin-core/docs/blob/master/gitian-building.md)

Development
---------------------
The Cerebralcoin repo's [root README](/README.md) contains relevant information on the development process and automated testing.

- [Developer Notes](developer-notes.md)
- [Productivity Notes](productivity.md)
- [Release Notes](release-notes.md)
- [Release Process](release-process.md)
- [Source Code Documentation (External Link)](https://dev.visucore.com/cerebralcoin/doxygen/)
- [Translation Process](translation_process.md)
- [Translation Strings Policy](translation_strings_policy.md)
- [JSON-RPC Interface](JSON-RPC-interface.md)
- [Unauthenticated REST Interface](REST-interface.md)
- [Shared Libraries](shared-libraries.md)
- [BIPS](bips.md)
- [Dnsseed Policy](dnsseed-policy.md)
- [Benchmarking](benchmarking.md)

### Resources
* Discuss on the [CerebralcoinTalk](https://cerebralcointalk.org/) forums, in the [Development & Technical Discussion board](https://cerebralcointalk.org/index.php?board=6.0).
* Discuss project-specific development on #cerebralcoin-core-dev on Freenode. If you don't have an IRC client, use [webchat here](http://webchat.freenode.net/?channels=cerebralcoin-core-dev).
* Discuss general Cerebralcoin development on #cerebralcoin-dev on Freenode. If you don't have an IRC client, use [webchat here](http://webchat.freenode.net/?channels=cerebralcoin-dev).

### Miscellaneous
- [Assets Attribution](assets-attribution.md)
- [cerebralcoin.conf Configuration File](cerebralcoin-conf.md)
- [Files](files.md)
- [Fuzz-testing](fuzzing.md)
- [Reduce Traffic](reduce-traffic.md)
- [Tor Support](tor.md)
- [Init Scripts (systemd/upstart/openrc)](init.md)
- [ZMQ](zmq.md)
- [PSBT support](psbt.md)

License
---------------------
Distributed under the [MIT software license](/COPYING).
This product includes software developed by the OpenSSL Project for use in the [OpenSSL Toolkit](https://www.openssl.org/). This product includes
cryptographic software written by Eric Young ([eay@cryptsoft.com](mailto:eay@cryptsoft.com)), and UPnP software written by Thomas Bernard.
