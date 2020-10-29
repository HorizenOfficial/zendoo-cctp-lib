# ZendooCctp: supporting Cross Chain Transfers for Zendoo Protocol

## Goal
Crypto functionalities should be regrouped in order to smooth development in two ways:
+ Make sure that if a new circuit functionality is to be added to a specific sidechain, only Sc_crypto_lib should be recompiled
+ Make sure that if a new curve/field/crypto functionality is added to ginger, it is propagately smoothly to zendooCctp/Sc_crypto_lib/Mc_crypto_lib upon inclusion

The libraries inclusion line should be:

         +----+Ginger+---+
         |       +       |
         |       |       |
         |       v       |
         |  Zendoo-cctp  |
         |       +       |
         |       |       |
         +-------+-------+
         |               |
         v               v
    Mc_crypto_lib   Sc_crypto_lib

Currently the main task of zendooCctp is:  
+ Sidechain Tx commitment creation and verification; scTxCommitment is created in MC and in SC Unit tests (UTs hereinafter) and verified in SC and in MC UTs  

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
- test support functions for all classes above
- quantities like sizes, to static_assert against them so to verify e.g. field is long enough to duly serialize app data

Along algaro indications, the main class should be named scTxCommitment and have kind of the following interface:
```
scTxCommitment(height)                                                --> or number of transactions to be globally handled
   addSc  (scId, amount, pubKey, withdrawalEpochLength,
           customData, constant, VerificationKey,
           txHash, outIdx)                                            --> Commitment [Note scId is hash of (txHash, outIdx) here, kind of redundant]
   addFwt (scId, amount, pubKey, txHash, outIdx)                      --> Commitment of all Fwts added so far
   addBwt (scId, amount, pubKey, txHash, outIdx)                      --> Commitment of all Bwts added so far
   addCert(scId, epochNumber, quality, endEpochBlockHash, scProof)    --> Commitment
   getCommitment()                                                    --> Commitment containing commitment for
                                                                          all scIds and all txes of each scId. Called on
                                                                          empty scTxCommitment gives default Commitment.
   getCommitmentForSc(scId)                                           --> Commitment containing commitment for
                                                                          all txes of for the specified scId. Called on scTxCommitment
                                                                          not containing scId gives default Commitment.
   getScCommitmentProof(scId)                                         --> ScCommitmentProof from sc commitment to (global) commitment
   VerifyScIsCommitted(scCommitment, scCommitmentProof, Commitment)   --> bool, where scCommitment      = getCommitmentForSc(scId)
                                                                                      scCommitmentProof = getScCommitmentProof(scId)
                                                                                      Commitment        = getCommitment()
   VerifyScIsNotCommitted(scId,
                          leftScId, leftFtsCommit, leftBtrsCommit, leftCertCommit, leftScCommitmentProof, 
                          rightScId, rightFtsCommit, rightBtrsCommit, rightCertCommit, rightScCommitmentProof,
                          Commitment)                                 --> bool, check that 
                                                                          left/right scLeaves are contiguous; leftScId < scId < rightScId
                                                                          left/right elements may or may not exist
                                                                          left/right*Commit objects come from add{Sc.Fwt,Bwt,Cert} functions
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

## Compilation notes
Picked branch sc_tx_commitment from SDK. It uses ad-hoc jar from zendoo_sc_cryptolib, got from Sasha via telegram. Some failing tests, under control  
In zendoo-sc-cryptolib branch where PoseidonHash related changes have been implemented is updatable_poseidon. rustc/cargo v 1.40.0 won't compile. Update to 1.47.0 would do with minor warnings. cargo fmt not called, would modify several files  
Imported on eclipse via File --> Import --> Maven --> Existing Maven Project --> Browse to root dir --> ok ok  
Eclipse plugin for Rust is called Corrosion: Help --> Eclipse Marketplace --> Search for Corrosion and install. To be tested

## Next steps
Another operation which cross chain transfer protocol requires is proof verification. Proofs are created in SC and in MC UTs and verified in MC and in SC UTs.  
Currently proof verification functions are not absorbed into zendooCctp and belong to mc_cryto_lib. However in next future we could move them and get an library inclusion flow as follows:  

    +------+Ginger+-----+
    |         +         |
    |         |         |
    |         v         |
    |    Zendoo-cctp    |
    |         +         |
    |         |         |
    |         v         |
    +-> sc_crypto-lib <-+

We should be able to do it since there are currently no crosschain related functionalities which belong to mainchain and not sidechain.  
(Daniele) possibly remove forwarding functions, so to eliminate inclusion of ginger from mc/sc_crypto_lib and just include zendooCctp from sc_crypto_lib

