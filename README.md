# ZendooCctp: supporting Cross Chain Transfers for Zendoo Protocol

## Goal
Crypto functionalities should be regrouped in order to smooth development in two ways:
+ Make sure that if a new circuit functionality is to be added to a specific sidechain, only Sc_crypto_lib should be recompiled
+ Make sure that if a new curve/field/crypto functionality is added to ginger, it is propagately smoothly to zendooCctp/Sc_crypto_lib/Mc_crypto_lib upon inclusion

The libraries inclusion line should be:

       ┌─────────────────────┬──> Mc_crypto_lib
    ginger ───> zendooCctp ──|
       └─────────────────────┴──> Sc_crypto_lib

or maybe

    ginger ───> zendooCctp ───────────┐
       |                              v
       └────────────────────────> Sc_crypto_lib

since, depending on commonalities among Mc/Sc_crypto_lib, Mc_crypto_lib could be completelly absorbed into zendooCctp; in fact I currently do not know of any Crosschain related functionalities which belong to mainchain and not sidechain!  
There are **two main task** that are emerging that zendooCctp is concerned with:  
+ Sidechain Tx commitment creation and verification; scTxCommitment is created in MC and in SC Unit tests (UTs hereinafter) and verified in SC and in MC UTs  
+ Proof verification *and possibly creation interface*; proof is created in SC and in MC UTs and verified in MC and in SC UTs

Todo: add explanation for functionalities of for other libraries  

## Design indications
1. scTxCommitment should be opaque to Mc/Sc; no tree structural stuff should be in control of Mc/Sc, except maybe tree height; ideally Mc/sc should not even know it's a Merkle tree
2. make explicit quantities like fields/proofs sizes, in order to static assert on and make sure hashing works as expected
3. (by Algaro) explicitly list quantities zendooCctp works on (e.g. amount, pubKey, nonce)
4. (by Algaro) make single function for each tx type (fwds, btr, certs)
5. (by Algaro) main class should be called scTxCommitment

## Tentative interface
ZendooCctp should contain references to the following objects:
- **Commitment**, with ctor/dtor/equality, serialization/deserialization starting from the very same attributes (to be checked, especially considering custom sc info)
- Flavours of **scTxCommitment**, **ScCommitmentProof**, with ctors/dtors/equality, serialization/deserialization, verifications
- **ScProof** and related classes like **scVerificationKey**
- test support functions for all classes above
- quantities like sizes, to static_assert against them so to verify e.g. field is long enough to duly serialize app data

Along algaro indications, the main class should be named scTxCommitment and have kind of the following interface:
```
scTxCommitment(height)                                                --> or number of transactions to be globally handled
   addSc  (scId, amount, pubKey, withdrawalEpochLength,
           customData, constant, VerificationKey,
           txHash, outIdx)                                            --> bool [Note scId is hash of (txHash, outIdx) here, kind of redundant]
   addFwt (scId, amount, pubKey, txHash, outIdx)                      --> bool
   addBwt (scId, amount, pubKey, txHash, outIdx)                      --> bool
   addCert(scId, epochNumber, quality, endEpochBlockHash, scProof)    --> bool
   getCommitment()                                                    --> Commitment object (see below), containing commitment for
                                                                          all scIds and all txes of each scId. Called on
                                                                          empty scTxCommitment gives default Commitment.
   getCommitmentForSc(scId)                                           --> Commitment object (see below) containing commitment for
                                                                          all txes of for the specified scId. Called on scTxCommitment
                                                                          not containing scId gives default Commitment.
   getScCommitmentProof(scId)                                         --> ScCommitmentProof from sc commitment to (global) commitment
   VerifyScIsCommitted(scCommitment, scCommitmentProof, Commitment)   --> bool, where scCommitment      = getCommitmentForSc(scId)
                                                                                      scCommitmentProof = getScCommitmentProof(scId)
                                                                                      Commitment        = getCommitment()

   VerifyScIsNotCommitted(scId, leftscCommitment, leftScCommitmentProof, 
                          rightScCommitment, rightScCommitmentProof,
                          Commitment)                                 --> bool, check that left/right scLeaves are contiguous inside

Commitment
   ctor                                --> default one, calling whatever Rust function needed to init field. Forbid copy
   dtor                                --> ensure RAII by encapsulating free function in dtor
   size                                --> unsigned int; this member should support compile time asserts against field size
   bool operator==(const Commitment &) --> TO BE ADDED INSTEAD OF zendoo_field_assert_eq (util in MC gtest).
   serialize/deserialize               --> only hex <--> field; move all logic to scTxCommitment;
                                           Serialization is needed to read/write scTxCommitmentRoot to MC block header.
                                           In MC Commitment should actually be exactly the type of CBLockHeader (rather than current CUint256)
   
Note: no createRandom(int seed). I understand need for random, I do not like seed type: why int and not string? It looks leak to me.
Used in UT only, where can be replaced by scTxCommitment.getCommitment() with "random" inputs fed via addFwt/Bwt.
I would like Commitment to support minimal functionalities for scTxCommitment operations.

ScCommitmentProof
   ctor                                       --> default one, calling whatever Rust function needed to init field. Forbid copy
   dtor                                       --> ensure RAII by encapsulating free function in dtor
   bool operator==(const ScCommitmentProof &) --> maybe useful to compare merkle paths in tests??
   serialize/deserialize                      --> needed in Sc

Note: verification of ScCommitmentProof has been moved to scTxCommitment, unlike current Sc implementation where it is feature of Merkle Path
```

with the following notes:
+ In SDK looks like leaves can be added as a list of leaves, not single ones. Duly extend interface above to accomodate for multiple txes.
+ **possibly** push down into ```VerifyTxIsNotCommitted``` low level functionalities like ```MerklePath.isNonEmptyRightMost/isLeftMost/leafIndex``` among others.

## Open points
- (Daniele) possibly remove forwarding functions, so to eliminate inclusion of ginger from mc/sc_crypto_lib and just include zendooCctp from sc_crypto_:lib

## Compilation notes
Picked branch sc_tx_commitment from SDK. It uses ad-hoc jar from zendoo_sc_cryptolib, got from Sasha via telegram. Some failing tests, under control  
In zendoo-sc-cryptolib branch where PoseidonHash related changes have been implemented is updatable_poseidon. rustc/cargo v 1.40.0 won't compile. Update to 1.47.0 would do with minor warnings. cargo fmt not called, would modify several files  
Imported on eclipse via File --> Import --> Maven --> Existing Maven Project --> Browse to root dir --> ok ok  
Eclipse plugin for Rust is called Corrosion: Help --> Eclipse Marketplace --> Search for Corrosion and install. To be tested

## LIST OF CURRENT CLASSES IN MC/SC, YET TO BE REFINED
```
CLASSES CURRENTLY IN MAINCHAIN

scProof
   size
   serialize/deserialize
   free

scVerificationKey
   size
   serialize/deserialize
   free
   bool operator==(const scProof &) --> TO BE ADDED INSTEAD OF zendoo_sc_vk_assert_eq

zendoo_verify_sc_proof

Tests
    zendoo_deserialize_sc_proof_from_file
    zendoo_generate_mc_test_params
    zendoo_create_mc_test_proof
    zendoo_sc_vk_assert_eq --> bool TO BE REPLACED BY EQUALITY OPERATOR ON SC_VK

THE STUFF BELOW ABSORBED BY scTxCommitmentTree or Commitment class
vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
Field
   size   --> TO ADD possibility to static_assert against it
   serialize/deserialize --> Maybe TO BE REMOVED: move logic to scTxCommitment; no ROGUE fields SERIALIZATION/DESERIALIZATION
   free --> private, hidden in dtor
   bool operator==(const Field &) --> TO BE ADDED INSTEAD OF zendoo_field_assert_eq

poseidonHash --> currently only in gtests. Possibly replaced by scTxCommitment and Field???
    ctor default and (personalization, personalization_len)
    update
    finalize
    reset
    dtor

zendoo_verify_ginger_merkle_path --> bool TO BE REPLACED BY scTxCommitment.VerifyScIsCommitted

ZendooGingerMerkleTree --> TO BE REPLACED BY scTxCommitment
    append
    finalize
    finalize_in_place
    root
    get_merkle_path(size_t leaf_index)
    reset
    get_empty_node   --> unused in MC. Maybe replaced by scTxCommitment.getCommiment() on default constructed scTxCommitment
    dtor

Tests
    zendoo_get_random_field    --> bool TO BE REPLACED BY getCommitment from adHoc tree, whose leaves may have some randomness
    zendoo_get_field_from_long --> bool TO BE REPLACED BY getCommitment from adHoc tree, whose leaves may have some randomness
    zendoo_field_assert_eq --> bool TO BE REPLACED BY EQUALITY OPERATOR ON FIELD
```

