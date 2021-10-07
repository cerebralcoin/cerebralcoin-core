 //Copyright (c) 2010 Satoshi Nakamoto
 //Copyright (c) 2009-2019 The Bitcoin Core developers 
// Copyright (c) 2019-2021 The Cerebralcoin Core developers
 //Distributed under the MIT software license, see the accompanying
 //file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <versionbitsinfo.h>

#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <arith_uint256.h>


const arith_uint256 maxUint = UintToArith256(
        uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

static void MineGenesis(CBlockHeader &genesisBlock, const uint256 &powLimit, bool noProduction) {
    if (noProduction) genesisBlock.nTime = std::time(0);
    genesisBlock.nNonce = 0;

    printf("NOTE: Genesis nTime = %u \n", genesisBlock.nTime);
    printf("WARN: Genesis nNonce (BLANK!) = %u \n", genesisBlock.nNonce);

    arith_uint256 besthash;
    memset(&besthash, 0xFF, 32);
    arith_uint256 hashTarget = UintToArith256(powLimit);
    printf("Target: %s\n", hashTarget.GetHex().c_str());
    arith_uint256 newhash = UintToArith256(genesisBlock.GetHash());
    while (newhash > hashTarget) {
        genesisBlock.nNonce++;
        if (genesisBlock.nNonce == 0) {
            printf("NONCE WRAPPED, incrementing time\n");
            ++genesisBlock.nTime;
        }
        // If nothing found after trying for a while, print status
        if ((genesisBlock.nNonce & 0xffff) == 0)
            printf("nonce %08X: hash = %s \r",
                   genesisBlock.nNonce, newhash.ToString().c_str(),
                   hashTarget.ToString().c_str());

        if (newhash < besthash) {
            besthash = newhash;
            printf("New best: %s\n", newhash.GetHex().c_str());
        }
        newhash = UintToArith256(genesisBlock.GetHash());
    }
    printf("\nGenesis nTime = %u \n", genesisBlock.nTime);
    printf("Genesis nNonce = %u \n", genesisBlock.nNonce);
    printf("Genesis nBits: %08x\n", genesisBlock.nBits);
    printf("Genesis Hash = %s\n", newhash.ToString().c_str());
    printf("Genesis Hash Merkle Root = %s\n", genesisBlock.hashMerkleRoot.ToString().c_str());
    printf("Genesis Hash Merkle Root = %s\n", genesisBlock.hashMerkleRoot.ToString().c_str());
}


static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    /*Cerebral
     * const char* pszTimestamp = "BBC 2/Jul/2021 Italy beat England on penalties to win Euro 2020";
	//const char* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    //v2
    const CScript genesisOutputScript = CScript() << ParseHex("040a5250da9b77dbc0055c01a8f0a5c65d84002267812548c0dc4d340a52ec3d1dcc748870a8ff412dee73a163ef33216f4f2e316cce85fe85d85f784a9cc08a42") << OP_CHECKSIG;
    //const CScript genesisOutputScript = CScript() << ParseHex("41040a5250da9b77dbc0055c01a8f0a5c65d84002267812548c0dc4d340a52ec3d1dcc748870a8ff412dee73a163ef33216f4f2e316cce85fe85d85f784a9cc08a42ac") << OP_CHECKSIG;
    //const CScript genesisOutputScript = CScript() << ParseHex("04b8faa7fde981a25bfe930596378b064c08bd61a4e58b9bfb2c45304306f533cf53f8c55a5f76dbf8360bd99a4a1b404e2151f6d85f0539c6d7de7b4e0c79fbb2") << OP_CHECKSIG;
    //const CScript genesisOutputScript = CScript() << ParseHex("040a5250da9b77dbc0055c01a8f0a5c65d84002267812548c0dc4d340a52ec3d1dcc748870a8ff412dee73a163ef33216f4f2e316cce85fe85d85f784a9cc08a42") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
    */
	const char* pszTimestamp = "18/Aug/2021 Maki Kaji, puzzle enthusiast, dies aged 69";
	//const CScript genesisOutputScript = CScript() << ParseHex("049cce3d4bdba242d103282ebb82bdbca968374a52ec34aa2116873292a3eb7628b48902edbb5be94c16a59550937a9177aa95989430fb95b34acb8137dcaf482a") << OP_CHECKSIG;
	const CScript genesisOutputScript = CScript() << ParseHex("04e832e2071eb2897af41739ceaa22e29f7bd465d90016b0c46721d877012b310af6682ce284e2a525258a7bfe727068fab11e3a3c7d06cc4371c9e0e30309425d") << OP_CHECKSIG;
	//const CScript genesisOutputScript = CScript() << ParseHex("41048ee737c49e9eeb206dd5fdc63a7ac700c2950787a8155d7779a04fb558abe33f9765b56579c06924023540c85ff4a26049dc9a0a1de478452b4fc91246f2d938ac") << OP_CHECKSIG;
	return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 210000;

        //consensus.BIP16Exception = uint256S("0x00000000f5cc3785e66f40b2ccfa9b44997b8c5d4df7c4af3f03d999b1582fe1");//uint256S("0x00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22");
        consensus.BIP16Exception = uint256S("0x00000000457ea038031d4a33e9c069fbc7f75c72d0b242fa043b1500c6ef4771");
        //consensus.BIP34Height = 227931;
        consensus.BIP34Height = 1;
        //consensus.BIP34Hash = uint256S("0x00000000f5cc3785e66f40b2ccfa9b44997b8c5d4df7c4af3f03d999b1582fe1");//uint256S("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
        consensus.BIP34Hash = uint256S("0x00000000457ea038031d4a33e9c069fbc7f75c72d0b242fa043b1500c6ef4771");
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        //consensus.BIP65Height = 388381; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        //consensus.BIP66Height = 363725; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        //consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetTimespan = 2.5 * 60 * 10; // retarget difficulty every 10 blocs or 1500s or 25 min
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1479168000; // November 15th, 2016.
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1510704000; // November 15th, 2017.

        // The best chain should have at least this much work.
        //consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000100010001");
        //consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000100010001");
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000001");

        // By default assume that the signatures in ancestors of this block are valid.
        //consensus.defaultAssumeValid = uint256S("0x0000000000000000000f1c54590ee18d15ec70e68c8cd4cfbadb1b4f11697eee"); //563378
        consensus.defaultAssumeValid = uint256S("0x00"); //563378

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfd;
        pchMessageStart[1] = 0xc3;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xdf;
        nDefaultPort = 2333;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 10; //240;
        m_assumed_chain_state_size = 3;
        //printf("In Main");

        //genesis = CreateGenesisBlock(1231006505, 2083236893, 0x1d00ffff, 1, 50 * COIN);

        //v2
        //genesis = CreateGenesisBlock(1626758204, 1024552765, 0x1e0ffff0, 1, 50 * COIN);
        //v3
        //genesis = CreateGenesisBlock(1627201294, 2843361029, 0x1e0ffff0, 1, 50 * COIN);
        //MineGenesis(genesis, consensus.powLimit, true);
        //MineGenesis(genesis, consensus.powLimit, true);
        //genesis = CreateGenesisBlock(std::time(nullptr), 546521654, 0x1d00ffff, 1, 50 * COIN);
        //MineGenesis(genesis, consensus.powLimit, true);

        //v4
        //genesis = CreateGenesisBlock(1627198333, 1619343371, 0x1e0ffff0, 1, 50 * COIN);
        //MineGenesis(genesis, consensus.powLimit, true);
        //v5
        //genesis = CreateGenesisBlock(1629258880, 1749843987, 0x1d00ffff, 1, 50 * COIN);
        //v6
        //genesis = CreateGenesisBlock(1629450099, 3832160289, 0x1d00ffff, 1, 50 * COIN);
        //v7
        genesis = CreateGenesisBlock(1629509439, 2729627803, 0x1d00ffff, 1, 50 * COIN);
        //MineGenesis(genesis, consensus.powLimit, true);
        printf("Mined already");
        consensus.hashGenesisBlock = genesis.GetHash();
        //assert(consensus.hashGenesisBlock == uint256S("0xaefd189abd663ae5fa99b45d3c5502ca6ea057f6b5b2fc7cf17cd9462a7311a1"));
        //assert(consensus.hashGenesisBlock == uint256S("0xaefd189abd663ae5fa99b45d3c5502ca6ea057f6b5b2fc7cf17cd9462a7311a1"));
        //assert(consensus.hashGenesisBlock == uint256S("0xaefd189abd663ae5fa99b45d3c5502ca6ea057f6b5b2fc7cf17cd9462a7311a1"));
        //assert(genesis.hashMerkleRoot == uint256S("0xc298c8e917156163387f87789bf0d933a4f1e9ef07d72250907af59b407f02ef"));
        //v2
        //printf("TEST GENESIS HASH: %s\n",consensus.hashGenesisBlock.ToString().c_str());
        //printf("TEST MERKLE ROOT: %s\n",genesis.hashMerkleRoot.ToString().c_str());
        //assert(consensus.hashGenesisBlock == uint256S("0x00000000f5cc3785e66f40b2ccfa9b44997b8c5d4df7c4af3f03d999b1582fe1"));
        //assert(genesis.hashMerkleRoot == uint256S("0xc298c8e917156163387f87789bf0d933a4f1e9ef07d72250907af59b407f02ef"));
        //v3
        //assert(consensus.hashGenesisBlock == uint256S("0x00000000ff6b4a379aefb19c1d37825581c6735a43baea81f2695e4dea10103e"));
        //assert(genesis.hashMerkleRoot == uint256S("0x51230da7fa6e5767e9409682ddd0694ca636a4c7bfbb3c6c74a91cfca9b3ef8a"));
        //v4
        //assert(consensus.hashGenesisBlock == uint256S("0x000000006669787882657a0ca14f77495203b8061ce0a8fedee79dc76aae8a0a"));
        //assert(genesis.hashMerkleRoot == uint256S("0xc298c8e917156163387f87789bf0d933a4f1e9ef07d72250907af59b407f02ef"));
        //v5
        //assert(consensus.hashGenesisBlock == uint256S("0x00000000d32b14992c89a97c781d1a27ea8453a39cf078b31ecf2fab0351c030"));
        //assert(genesis.hashMerkleRoot == uint256S("0xc298c8e917156163387f87789bf0d933a4f1e9ef07d72250907af59b407f02ef"));
        //v6
        //assert(consensus.hashGenesisBlock == uint256S("0x0000000097b56d1cc5596b6519c04d470326017760cec18918e36591c7a5f223"));
        //assert(genesis.hashMerkleRoot == uint256S("0x79d033324d9d79e14a9479244e55544980ca140d53c033220b5871949e749737"));
        //v7
        //assert(consensus.hashGenesisBlock == uint256S("0x000000002856a8528ffa94ec60cfb54aa817eef6ef27861841eaa8d3cb14dfec"));
        //assert(genesis.hashMerkleRoot == uint256S("0x7a6d73e5972584e6c0243f3b680c5d38b321f5ab934468d72cfe82f08ff4f0cc"));
        //v8
        //assert(consensus.hashGenesisBlock == uint256S("0x000000002856a8528ffa94ec60cfb54aa817eef6ef27861841eaa8d3cb14dfec"));
        //assert(genesis.hashMerkleRoot == uint256S("0x7a6d73e5972584e6c0243f3b680c5d38b321f5ab934468d72cfe82f08ff4f0cc"));
        //v9
        assert(consensus.hashGenesisBlock == uint256S("0x00000000457ea038031d4a33e9c069fbc7f75c72d0b242fa043b1500c6ef4771"));
        assert(genesis.hashMerkleRoot == uint256S("0x9d603b9b03405bc64421863c3263f852bc718744accf0376802392e668fd59e2"));

        //assert(consensus.hashGenesisBlock == uint256S("0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"));
        //assert(genesis.hashMerkleRoot == uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));

        //assert(genesis.hashMerkleRoot == uint256S("0xa4b662f9f2c7dfd099217f87292af730ed7284313c0f78de3903b83c8ebbe701"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.

        //vSeeds.emplace_back("seed.cerebralcoin.sipa.be"); // Pieter Wuille, only supports x1, x5, x9, and xd
        //vSeeds.emplace_back("dnsseed.bluematt.me"); // Matt Corallo, only supports x9
        //vSeeds.emplace_back("dnsseed.cerebralcoin.dashjr.org"); // Luke Dashjr
        //vSeeds.emplace_back("seed.cerebralcoinstats.com"); // Christian Decker, supports x1 - xf
        //vSeeds.emplace_back("seed.cerebralcoin.jonasschnelli.ch"); // Jonas Schnelli, only supports x1, x5, x9, and xd
        //vSeeds.emplace_back("seed.btc.petertodd.org"); // Peter Todd, only supports x1, x5, x9, and xd
        //vSeeds.emplace_back("seed.cerebralcoin.sprovoost.nl"); // Sjors Provoost
        //vSeeds.emplace_back("dnsseed.emzy.de"); // Stephan Oeste
        vSeeds.clear();

        //base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,28);
        //base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        //base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,'C');
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,'c');
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,'+');
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "ceb";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                { 0, uint256S("0x00000000457ea038031d4a33e9c069fbc7f75c72d0b242fa043b1500c6ef4771")}
            }
        };

        //chainTxData = ChainTxData{
         //   // Data from rpc: getchaintxstats 4096 0000000000000000000f1c54590ee18d15ec70e68c8cd4cfbadb1b4f11697eee
           // /* nTime    */ 1550374134,
            ///* nTxCount */ 383732546,
            ///* dTxRate  */ 3.685496590998308
        //};
        chainTxData = ChainTxData{};

        /* disable fallback fee on mainnet */
        m_fallback_fee_enabled = false;
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Exception = uint256S("0x0000000023a6fd0899110005e2c214d8fc6cd9eaee7839cdeb3ada175c53aa2b");
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256S("0x0000000023a6fd0899110005e2c214d8fc6cd9eaee7839cdeb3ada175c53aa2b");
        consensus.BIP65Height = 1; // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP66Height = 1; // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400; // March 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1462060800; // May 1st 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1493596800; // May 1st 2017

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000000000000");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0000000000000037a8cd3e06cd5edbfe9dd1dbcc5dacab279376ef7cfc2b4c75"); //1354312

        pchMessageStart[0] = 0x0b;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x09;
        pchMessageStart[3] = 0x07;
        nDefaultPort = 2332;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 30;
        m_assumed_chain_state_size = 2;

        //genesis = CreateGenesisBlock(1627365354, 2903571056, 0x1d00ffff, 1, 50 * COIN);
        //genesis = CreateGenesisBlock(1629258535, 0, 0x1d00ffff, 1, 50 * COIN);
        genesis = CreateGenesisBlock(1629511329, 545046441, 0x1d00ffff, 1, 50 * COIN);
        //MineGenesis(genesis, consensus.powLimit, true);
        printf("Mined Test  already");

        consensus.hashGenesisBlock = genesis.GetHash();
        //MineGenesis(genesis, consensus.powLimit, true);
        //assert(consensus.hashGenesisBlock == uint256S("0x142090789a55e00150fc6a9250e85c5e1e2f98ddc3b3b6ab404412863b1e8749"));
        //assert(genesis.hashMerkleRoot == uint256S("0xa4b662f9f2c7dfd099217f87292af730ed7284313c0f78de3903b83c8ebbe701"));
        //printf("TEST GENESIS HASH: %s\n",consensus.hashGenesisBlock.ToString().c_str());
        //printf("TEST MERKLE ROOT: %s\n",genesis.hashMerkleRoot.ToString().c_str());
        //assert(consensus.hashGenesisBlock == uint256S("0x0000000055e9f5f871b154fc42bbe5c64f3872ccf3c728371e6d271d3e9c4d08"));
        //assert(genesis.hashMerkleRoot == uint256S("0xc298c8e917156163387f87789bf0d933a4f1e9ef07d72250907af59b407f02ef"));
        assert(consensus.hashGenesisBlock == uint256S("0x0000000023a6fd0899110005e2c214d8fc6cd9eaee7839cdeb3ada175c53aa2b"));
        assert(genesis.hashMerkleRoot == uint256S("0x9d603b9b03405bc64421863c3263f852bc718744accf0376802392e668fd59e2"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        //vSeeds.emplace_back("testnet-seed.cerebralcoin.jonasschnelli.ch");
        //vSeeds.emplace_back("seed.tbtc.petertodd.org");
        //vSeeds.emplace_back("seed.testnet.cerebralcoin.sprovoost.nl");
        //vSeeds.emplace_back("testnet-seed.bluematt.me"); // Just a static list of stable node(s), only supports x9

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tceb";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;


        checkpointData = {
            {
                {0, uint256S("0x0000000023a6fd0899110005e2c214d8fc6cd9eaee7839cdeb3ada175c53aa2b")},
            }
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096 0000000000000037a8cd3e06cd5edbfe9dd1dbcc5dacab279376ef7cfc2b4c75
            /* nTime    */ 1531929919,
            /* nTxCount */ 19438708,
            /* dTxRate  */ 0.626
        };

        /* enable fallback fee on testnet */
        m_fallback_fee_enabled = true;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Exception = uint256();
        consensus.BIP34Height = 500; // BIP34 activated on regtest (Used in functional tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in functional tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in functional tests)
        consensus.powLimit = uint256S("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        //printf("In reg");
        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbe;
        pchMessageStart[2] = 0xb3;
        pchMessageStart[3] = 0xdd;
        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateVersionBitsParametersFromArgs(args);

        //genesis = CreateGenesisBlock(1627368347, 2131540328, 0x1d00ffff, 1, 50 * COIN);
        genesis = CreateGenesisBlock(1629511983, 907358544, 0x1d00ffff, 1, 50 * COIN);
        //MineGenesis(genesis, consensus.powLimit, true);
        consensus.hashGenesisBlock = genesis.GetHash();
        //MineGenesis(genesis, consensus.powLimit, true);
        //assert(consensus.hashGenesisBlock == uint256S("0xd079abaae9b0a9282a0bb30e354c813f8d30f3f487e6cbc4688e07946aec5db2"));
        //assert(genesis.hashMerkleRoot == uint256S("0xa4b662f9f2c7dfd099217f87292af730ed7284313c0f78de3903b83c8ebbe701"));
        assert(consensus.hashGenesisBlock == uint256S("0x00000000644e8e7b459483dc89f0e7e918c056bc6d6127e8ce0b32df3551d2d4"));
        assert(genesis.hashMerkleRoot == uint256S("0x9d603b9b03405bc64421863c3263f852bc718744accf0376802392e668fd59e2"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {
                {0, uint256S("0x00000000644e8e7b459483dc89f0e7e918c056bc6d6127e8ce0b32df3551d2d4")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "rceb";

        /* enable fallback fee on regtest */
        m_fallback_fee_enabled = true;
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
    void UpdateVersionBitsParametersFromArgs(const ArgsManager& args);
};

void CRegTestParams::UpdateVersionBitsParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams;
        boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
        if (vDeploymentParams.size() != 3) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end");
        }
        int64_t nStartTime, nTimeout;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld\n", vDeploymentParams[0], nStartTime, nTimeout);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams(gArgs));
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}
// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2019 The Kryptofranc Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//#include <chainparams.h>
//#include <arith_uint256.h>
//
//#include <chainparamsseeds.h>
//#include <consensus/merkle.h>
//#include <tinyformat.h>
//#include <util/system.h>
//#include <util/strencodings.h>
//#include <versionbitsinfo.h>
//
//#include <assert.h>
//
//#include <boost/algorithm/string/classification.hpp>
//#include <boost/algorithm/string/split.hpp>
//
//
////Mining algorithm
//
//
//const arith_uint256 maxUint = UintToArith256(
//        uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
//
//static void MineGenesis(CBlockHeader &genesisBlock, const uint256 &powLimit, bool noProduction) {
//    if (noProduction) genesisBlock.nTime = std::time(0);
//    genesisBlock.nNonce = 0;
//
//    printf("NOTE: Genesis nTime = %u \n", genesisBlock.nTime);
//    printf("WARN: Genesis nNonce (BLANK!) = %u \n", genesisBlock.nNonce);
//
//    arith_uint256 besthash;
//    memset(&besthash, 0xFF, 32);
//    arith_uint256 hashTarget = UintToArith256(powLimit);
//    printf("Target: %s\n", hashTarget.GetHex().c_str());
//    arith_uint256 newhash = UintToArith256(genesisBlock.GetHash());
//    while (newhash > hashTarget) {
//        genesisBlock.nNonce++;
//        if (genesisBlock.nNonce == 0) {
//            printf("NONCE WRAPPED, incrementing time\n");
//            ++genesisBlock.nTime;
//        }
//        // If nothing found after trying for a while, print status
//        if ((genesisBlock.nNonce & 0xffff) == 0)
//            printf("nonce %08X: hash = %s \r",
//                   genesisBlock.nNonce, newhash.ToString().c_str(),
//                   hashTarget.ToString().c_str());
//
//        if (newhash < besthash) {
//            besthash = newhash;
//            printf("New best: %s\n", newhash.GetHex().c_str());
//        }
//        newhash = UintToArith256(genesisBlock.GetHash());
//    }
//    printf("\nGenesis nTime = %u \n", genesisBlock.nTime);
//    printf("Genesis nNonce = %u \n", genesisBlock.nNonce);
//    printf("Genesis nBits: %08x\n", genesisBlock.nBits);
//    printf("Genesis Hash = %s\n", newhash.ToString().c_str());
//    printf("Genesis Hash Merkle Root = %s\n", genesisBlock.hashMerkleRoot.ToString().c_str());
//    printf("Genesis Hash Merkle Root = %s\n", genesisBlock.hashMerkleRoot.ToString().c_str());
//}
//
//
//static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
//{
//    CMutableTransaction txNew;
//    txNew.nVersion = 1;
//    txNew.vin.resize(1);
//    txNew.vout.resize(1);
//    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
//    txNew.vout[0].nValue = genesisReward;
//    txNew.vout[0].scriptPubKey = genesisOutputScript;
//
//    CBlock genesis;
//    genesis.nTime    = nTime;
//    genesis.nBits    = nBits;
//    genesis.nNonce   = nNonce;
//    genesis.nVersion = nVersion;
//    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
//    genesis.hashPrevBlock.SetNull();
//    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
//    return genesis;
//}
//
///**
// * Build the genesis block. Note that the output of its generation
// * transaction cannot be spent since it did not originally exist in the
// * database.
// *
// * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
// *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
// *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
// *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
// *   vMerkleTree: 4a5e1e
// */
//static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
//{
//    const char* pszTimestamp = "30/05/2019 RT: Beijing has accused Washington of engaging in naked economic terrorism.";
//    const CScript genesisOutputScript = CScript() << ParseHex("04bff16e305296ab93ee46fad2593b3fc13261aff978bd02732012956d4e6ba2cdb30e168adfef3fb3770cdd1857e3d1ba86a55c8072ec8d343767158a781a7472") << OP_CHECKSIG;
//    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
//}
//
///**
// * Main network
// */
//class CMainParams : public CChainParams {
//public:
//    CMainParams() {
//        strNetworkID = "main";
//        consensus.nSubsidyHalvingInterval = 525600/2.5;
//
//        consensus.BIP16Exception = uint256S("0x00067ca5a4b9f4bb12eb66dbdbe8799d4089da90c65ac7b8db2aa475da7dc690");
//        consensus.BIP34Height = 1; // optimization starting from 1;
//        consensus.BIP34Hash = uint256S("0x00067ca5a4b9f4bb12eb66dbdbe8799d4089da90c65ac7b8db2aa475da7dc690");
//        consensus.BIP65Height = 1; // optimization starting from 1; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
//        consensus.BIP65Height = 1; // optimization starting from 1; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
//        //consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
//        consensus.powLimit=uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
//        //consensus.powLimit=uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
//
//        consensus.nPowTargetTimespan =   2.5 * 60 * 10;
//        consensus.nPowTargetSpacing = 2.5 * 60 ;
//
//
//        assert(consensus.nPowTargetTimespan>= consensus.nPowTargetSpacing );
//
//        consensus.fPowAllowMinDifficultyBlocks = false;
//        consensus.fPowNoRetargeting = false;
//        consensus.nRuleChangeActivationThreshold = 1916*4; // 95% of 2016
//        consensus.nMinerConfirmationWindow = 2016*4;
//        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
//        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
//        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008
//
//        // Deployment of BIP68, BIP112, and BIP113.
//        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
//        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800; // May 1st, 2016
//        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017
//
//        // Deployment of SegWit (BIP141, BIP143, and BIP147)
//        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
//        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1479168000; // November 15th, 2016.
//        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1510704000; // November 15th, 2017.
//
//        // The best chain should have at least this much work.
//        //consensus.nMinimumChainWork = uint256S("0x1d00fff0");
//        consensus.nMinimumChainWork = uint256S("000000000000000000000000000000000000000000000000fa631fb237b72ada");
//
//        // By default assume that the signatures in ancestors of this block are valid.
//        consensus.defaultAssumeValid = uint256S("0x00"); //563378
//
//        /**
//         * The message start string is designed to be unlikely to occur in normal data.
//         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
//         * a large 32-bit integer with any alignment.
//         */
//        pchMessageStart[0] = 0x4c;
//        pchMessageStart[1] = 0x53;
//        pchMessageStart[2] = 0x44;
//        pchMessageStart[3] = 0x21;
//        nDefaultPort = 1789;
//        nPruneAfterHeight = 1000;
//        m_assumed_blockchain_size = 10; //10
//        m_assumed_chain_state_size = 3; //3
//
//        //genesis = CreateGenesisBlock(std::time(0), 0, 0x1d00ffff, 1, 50 * COIN);
//        //MineGenesis(genesis, consensus.powLimit, true);
//        //exit (0);
//        genesis = CreateGenesisBlock(1559254695,2268597939,0x1d00ffff,1, 50*COIN);
//        consensus.hashGenesisBlock = genesis.GetHash();
//        assert(consensus.hashGenesisBlock == uint256S("0x00000000cb6124045a6aee1ffb4c5c42f43deddc4b3831a2f978c3f650871c05"));
//        assert(genesis.hashMerkleRoot == uint256S("0xce040eb4a18c95973ee0ca618979b23a61fcbf46b65f2621fdf7aadf35e4f026"));
//
//        // Note that of those which support the service bits prefix, most only support a subset of
//        // possible options.
//        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
//        // service bits we want, but we should get them updated to support all service bits wanted by any
//        // release ASAP to avoid it where possible.
//        //vSeeds.emplace_back("seed1.kryptofranc.net"); // removed
//        //vSeeds.emplace_back("seed2.kryptofranc.net"); // removed
//        //vSeeds.emplace_back("seed3.kryptofranc.net"); // removed
//        //vSeeds.emplace_back("seed4.kryptofranc.net"); //
//        vFixedSeeds.clear();
//        vSeeds.clear();
//
//        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,'C');
//        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,'c');
//        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,'+');
//        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
//        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};
//
//        bech32_hrp = "ceb";
//
//        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));
//
//        fDefaultConsistencyChecks = false;
//        fRequireStandard = true;
//        fMineBlocksOnDemand = false;
//
//        checkpointData = {
//                {
//                        { 1, uint256S("000000009419e2f790c8798163414f63dcc2a2409368e7d34b95aa382146b4f4")}
//
//
//
//
//                }
//        };
//
//        chainTxData = ChainTxData{
//        };
//
//        /* disable fallback fee on mainnet */
//        m_fallback_fee_enabled = false;
//    }
//};
//
///**
// * Testnet (v3)
// */
//class CTestNetParams : public CChainParams {
//public:
//    CTestNetParams() {
//        strNetworkID = "test";
//        consensus.nSubsidyHalvingInterval = 525600/2.5;
//
//        consensus.BIP16Exception = uint256S("0x00067ca5a4b9f4bb12eb66dbdbe8799d4089da90c65ac7b8db2aa475da7dc690");
//        consensus.BIP34Height = 1; // optimization starting from 1;
//        consensus.BIP34Hash = uint256S("0x00067ca5a4b9f4bb12eb66dbdbe8799d4089da90c65ac7b8db2aa475da7dc690");
//        consensus.BIP65Height = 1; // optimization starting from 1; // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
//        consensus.BIP65Height = 1; // optimization starting from 1; // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
//        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
//        //consensus.powLimit("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
//        consensus.nPowTargetSpacing = 2.5 * 60 * 10; // retarget difficulty every 10 blocs or 1500s or 25 min
//        consensus.nPowTargetTimespan =   2.5 * 60 ; // block generated every...
//        assert(consensus.nPowTargetTimespan<= consensus.nPowTargetSpacing );
//        consensus.fPowAllowMinDifficultyBlocks = true;
//        consensus.fPowNoRetargeting = false;
//        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
//        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
//        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
//        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
//        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008
//
//        // Deployment of BIP68, BIP112, and BIP113.
//        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
//        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400; // March 1st, 2016
//        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017
//
//        // Deployment of SegWit (BIP141, BIP143, and BIP147)
//        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
//        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1462060800; // May 1st 2016
//        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1493596800; // May 1st 2017
//
//        // The best chain should have at least this much work.
//        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000000000000");
//
//        // By default assume that the signatures in ancestors of this block are valid.
//        consensus.defaultAssumeValid = uint256S("0x00"); //1354312
//
//        pchMessageStart[0] = 0x0b;
//        pchMessageStart[1] = 0x11;
//        pchMessageStart[2] = 0x09;
//        pchMessageStart[3] = 0x07;
//        nDefaultPort = 11789;
//        nPruneAfterHeight = 1000;
//        m_assumed_blockchain_size = 10;
//        m_assumed_chain_state_size = 2;
//
//        genesis = CreateGenesisBlock(1559254695,2268597939,0x1d00ffff,1, 50*COIN);
//        consensus.hashGenesisBlock = genesis.GetHash();
//        assert(consensus.hashGenesisBlock == uint256S("0x00000000cb6124045a6aee1ffb4c5c42f43deddc4b3831a2f978c3f650871c05"));
//        assert(genesis.hashMerkleRoot == uint256S("0xce040eb4a18c95973ee0ca618979b23a61fcbf46b65f2621fdf7aadf35e4f026"));
//
//
//        vFixedSeeds.clear();
//        vSeeds.clear();
//
//        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
//        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
//        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
//        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
//        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
//
//        bech32_hrp = "tkf";
//
//        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));
//
//        fDefaultConsistencyChecks = false;
//        fRequireStandard = false;
//        fMineBlocksOnDemand = true;
//
//
//        checkpointData = {
//                {
//                        {0, uint256S("0x00067ca5a4b9f4bb12eb66dbdbe8799d4089da90c65ac7b8db2aa475da7dc690")},
//                }
//        };
//
//        chainTxData = ChainTxData{
//                // Data from rpc: getchaintxstats 4096 0000000000000037a8cd3e06cd5edbfe9dd1dbcc5dacab279376ef7cfc2b4c75
//                /* nTime    */ 0,
//                /* nTxCount */ 0,
//                /* dTxRate  */ 0
//        };
//
//        /* enable fallback fee on testnet */
//        m_fallback_fee_enabled = true;
//    }
//};
//
///**
// * Regression test
// */
//class CRegTestParams : public CChainParams {
//public:
//    explicit CRegTestParams(const ArgsManager& args) {
//        strNetworkID = "regtest";
//        consensus.nSubsidyHalvingInterval = 1;
//        consensus.BIP16Exception = uint256();
//        consensus.BIP34Height = 1; // BIP34 activated on regtest (Used in functional tests)
//        consensus.BIP34Hash = uint256();
//        consensus.BIP65Height = 1; // optimization starting from 1; // BIP65 activated on regtest (Used in functional tests)
//        consensus.BIP65Height = 1; // optimization starting from 1; // BIP66 activated on regtest (Used in functional tests)
//        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
//
//        consensus.nPowTargetSpacing = 2.5 * 60 * 10; // retarget difficulty every 10 blocs or 1500s or 25 min
//        consensus.nPowTargetTimespan =   2.5 * 60 ; // block generated every...
//        assert(consensus.nPowTargetTimespan<= consensus.nPowTargetSpacing );
//        consensus.fPowAllowMinDifficultyBlocks = true;
//        consensus.fPowNoRetargeting = true;
//        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
//        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
//        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
//        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
//        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
//        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
//        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
//        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
//        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
//        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
//        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
//
//        // The best chain should have at least this much work.
//        consensus.nMinimumChainWork = uint256S("0x00");
//
//        // By default assume that the signatures in ancestors of this block are valid.
//        consensus.defaultAssumeValid = uint256S("0x00");
//
//        pchMessageStart[0] = 0xfa;
//        pchMessageStart[1] = 0xbf;
//        pchMessageStart[2] = 0xb5;
//        pchMessageStart[3] = 0xda;
//        nDefaultPort = 211789;
//        nPruneAfterHeight = 1000;
//        m_assumed_blockchain_size = 0;
//        m_assumed_chain_state_size = 0;
//
//        UpdateVersionBitsParametersFromArgs(args);
//
//        genesis = CreateGenesisBlock(1559254695,2268597939,0x1d00ffff,1, 50*COIN);
//        consensus.hashGenesisBlock = genesis.GetHash();
//        assert(consensus.hashGenesisBlock == uint256S("0x00000000cb6124045a6aee1ffb4c5c42f43deddc4b3831a2f978c3f650871c05"));
//        assert(genesis.hashMerkleRoot == uint256S("0xce040eb4a18c95973ee0ca618979b23a61fcbf46b65f2621fdf7aadf35e4f026"));
//
//        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
//        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.
//
//        fDefaultConsistencyChecks = true;
//        fRequireStandard = false;
//        fMineBlocksOnDemand = true;
//
//        checkpointData = {
//                {
//                        {0, uint256S("0x00067ca5a4b9f4bb12eb66dbdbe8799d4089da90c65ac7b8db2aa475da7dc690")},
//                }
//        };
//
//        chainTxData = ChainTxData{
//                0,
//                0,
//                0
//        };
//
//        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
//        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
//        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
//        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
//        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
//
//        bech32_hrp = "kfrt";
//
//        /* enable fallback fee on regtest */
//        m_fallback_fee_enabled = true;
//    }
//
//    /**
//     * Allows modifying the Version Bits regtest parameters.
//     */
//    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
//    {
//        consensus.vDeployments[d].nStartTime = nStartTime;
//        consensus.vDeployments[d].nTimeout = nTimeout;
//    }
//    void UpdateVersionBitsParametersFromArgs(const ArgsManager& args);
//};
//
//void CRegTestParams::UpdateVersionBitsParametersFromArgs(const ArgsManager& args)
//{
//    if (!args.IsArgSet("-vbparams")) return;
//
//    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
//        std::vector<std::string> vDeploymentParams;
//        boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
//        if (vDeploymentParams.size() != 3) {
//            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end");
//        }
//        int64_t nStartTime, nTimeout;
//        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
//            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
//        }
//        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
//            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
//        }
//        bool found = false;
//        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
//            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
//                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout);
//                found = true;
//                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld\n", vDeploymentParams[0], nStartTime, nTimeout);
//                break;
//            }
//        }
//        if (!found) {
//            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
//        }
//    }
//}
//
//static std::unique_ptr<const CChainParams> globalChainParams;
//
//const CChainParams &Params() {
//    assert(globalChainParams);
//    return *globalChainParams;
//}
//
//std::unique_ptr<const CChainParams> CreateChainParams(const std::string& chain)
//{
//    if (chain == CBaseChainParams::MAIN)
//        return std::unique_ptr<CChainParams>(new CMainParams());
//    else if (chain == CBaseChainParams::TESTNET)
//        return std::unique_ptr<CChainParams>(new CTestNetParams());
//    else if (chain == CBaseChainParams::REGTEST)
//        return std::unique_ptr<CChainParams>(new CRegTestParams(gArgs));
//    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
//}
//
//void SelectParams(const std::string& network)
//{
//    SelectBaseParams(network);
//    globalChainParams = CreateChainParams(network);
//}
