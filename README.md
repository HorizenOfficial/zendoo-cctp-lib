# zendoo-CCTP-lib: supporting Cross Chain Transfers for Zendoo Protocol

## Goal
Crypto functionalities should be regrouped in order to smooth development in two ways:
+ Make sure that if a new circuit functionality is to be added to a specific sidechain, only zendoo-sc-cryptolib should be recompiled
+ Make sure that if a new curve/field/crypto functionality is added to ginger-lib, it is propagately smoothly to zendoo-CCTP-lib/zendoo-sc-cryptolib/zendoo-mc-cryptolib upon inclusion

The libraries inclusion line should be:

           +----+ginger-lib+---+
           |         +         |
           |         |         |
           |         v         |
           |  zendoo-CCTP-lib  |
           |         +         |
           |         |         |
           +---------+---------+
           |                   |
           v                   v
       zendoo-mc           zendoo-sc
       cryptolib           cryptolib

Currently the main task of zendoo-CCTP-lib is:  
+ Sidechain Tx commitment creation and verification; commitments are created in MC and in SC Unit tests (UTs hereinafter) and verified in MC and SC  

## Design indications
1. commitments should be opaque to Mc/Sc; no tree structural stuff should be in control of Mc/Sc, except maybe tree height; ideally Mc/sc should not even know it's a Merkle tree
2. make explicit quantities like fields/proofs sizes, in order to static assert on and make sure hashing works as expected
3. (by Algaro) explicitly list quantities zendoo-CCTP-lib works on (e.g. amount, pubKey, nonce)
4. (by Algaro) make single function for each tx type (fwds, btr, certs)  

## Tentative interface
zendoo-CCTP-lib should contain references to the following objects:
- **Commitment**, with ctor/dtor/equality, serialization/deserialization starting from the very same attributes (to be checked, especially considering custom sc info)
- Flavours of **scTxCommitment**, **ScCommitmentProof**, with ctors/dtors/equality, serialization/deserialization, verifications
- test support functions for all classes above
- quantities like sizes, to static_assert against them so to verify e.g. field is long enough to duly serialize app data

**Note: Mapping from single attributes (scId, amount pkHash) to one or more field must be specified here,
  since it's common to both sc and mc**
```
aliveScTxCommitmentTree
   addScC(scId, amount, pubKey,withdrawalEpochLength,
          customData, constant,
          CertVerificationKey,
          BtrVerificationKey,
          CswVerificationKey,
          txHash, outIdx)                              --> bool [Note: BtrVerificationKey and  CswVerificationKey are optional]
   addFwt(scId, amount, pubKey, txHash, outIdx)        --> bool
   addBtr(scId, amount, pubKey, txHash, outIdx)        --> bool
   addCrt(scId, epochNumber, quality,
          certDataHash,
          BTList,
          customFieldsMerkleRoot,
          endCumulativeScTxCommitmentTreeRoot)         --> bool [Note: endCumulativeScTxCommitmentTreeRoot to be added to Cert;
                                                                       certDataHash of *this* cert, for which addCrt is called;
                                                                       both top and lower quality certs must be processed]
   getScCCommitment(scId)                              --> Commitment
   getFwtCommitment(scId)                              --> Commitment
   getBwtCommitment(scId)                              --> Commitment
   getCrtCommitment(scId)                              --> Commitment
--------------------------------------------------------------------------------------------------------------------------------
ceasedScTxCommitmentTree
   addCsw(scId, amount, nullifier, pkHash,
          ActiveCertDataHash)                          --> bool
   getaddCswCommitment(scId)                           --> Commitment
--------------------------------------------------------------------------------------------------------------------------------
Common methods for alive/ceased ScTxCommitmentTree
   getCommitmentForSc(scId)                            --> Commitment [Note: containing commitment for
                                                                             all txes of for the specified scId. Called on scTxCommitmentBuilder
                                                                             not containing scId gives default Commitment].
   getCommitment()                                     --> Commitment [Note: containing commitment for
                                                                             all scIds and all txes of each scId. Called on
                                                                             empty scTxCommitmentBuilder gives default Commitment].

   getScExistenceProof(scId)                           --> ScCommitmentProof [Note: from sc commitment to (global) commitment]
   getScAbsenceProof(scId)                             --> ScAbsenceProof    [Note: from missing scId to (global) commitment]

   VerifyScCommitment(scCommitment,
                      scCommitmentProof, Commitment)   --> bool, where scCommitment      = getCommitmentForSc(scId)
                                                                       scCommitmentProof = getScCommitmentProof(scId)
                                                                       Commitment        = getCommitment()

   VerifyScAbsence(scId, ScAbsenceProof, Commitment)   --> bool, where scId is missing sidechain id
                                                                       ScAbsenceProof = getScAbsenceProof(scId),
                                                                       Commitment        = getCommitment()  
--------------------------------------------------------------------------------------------------------------------------------
Commitment [Note: essentially a wrapper for a field]
   ctor                                --> default one, calling whatever Rust function needed to init field. Forbid copy
   dtor                                --> ensure RAII by encapsulating free function in dtor
   size                                --> unsigned int; this member should support compile time asserts against field size
   bool operator==(const Commitment &) --> TO BE ADDED INSTEAD OF zendoo_field_assert_eq (util in MC gtest).
   serialize/deserialize               --> only hex <--> field; move all logic to scTxCommitmentBuilder;
                                           Serialization is needed to read/write scTxCommitmentRoot to MC block header.
                                           In MC Commitment should actually be exactly the type of CBLockHeader (rather than current CUint256)
   
Note: no createRandom(int seed). I understand need for random, I do not like seed type: why int and not string? It looks leak to me.
Used in UT only, where can be replaced by scTxCommitmentBuilder.getCommitment() with "random" inputs fed via addFwt/Bwt.
I would like Commitment to support minimal functionalities for scTxCommitmentBuilder operations.

ScCommitmentProof [Note: essentially a merkle path from given sc-related subtree to global commitment]
   ctor                                       --> default one, calling whatever Rust function needed to init field. Forbid copy
   dtor                                       --> ensure RAII by encapsulating free function in dtor
   bool operator==(const ScCommitmentProof &) --> maybe useful to compare merkle paths in tests??
   serialize/deserialize                      --> needed in Sc

ScAbsenceProof [Note: contains one or two merkle path for neighbors subtrees and the scId of there neighbors]
   members:
       leftFtsCommit,  leftBtrsCommit,  leftCertCommit,  leftScCommitmentProof
       rightFtsCommit, rightBtrsCommit, rightCertCommit, rightScCommitmentProof
   ctor                                       --> default one, calling whatever Rust function needed to init field. Forbid copy
   dtor                                       --> ensure RAII by encapsulating free function in dtor
   bool operator==(const ScCommitmentProof &) --> maybe useful to compare merkle paths in tests??
   serialize/deserialize                      --> needed in Sc
```

with the following notes:
+ In SDK looks like leaves can be added as a list of leaves, not single ones. Duly extend interface above to accomodate for multiple txes.
+ **possibly** push down into ```VerifyTxIsNotCommitted``` low level functionalities like ```MerklePath.isNonEmptyRightMost/isLeftMost/leafIndex``` among others.

## ScTxCommitmentTree structure

```
 ALIVE SIDECHAIN SUBTREE STRUCTURE            CEASED SIDECHAIN SUBTREE STRUCTURE

|  +------+                                      |  +------+
|  |Fwt_1 |\                                     |  |Csw_1 |\
|  +------+ \                                    |  +------+ \
|            o                                   |            o
|  +------+ / \                                  |  +------+ / \
|  |Fwt_2 |/   \                                 |  |Csw_2 |/   \
|  +------+     +------+                         |  +------+     +-----+
|               | FtMt |-----+                   |               |CswMt|-----+
|   ......      +------+     |                   |   ......      +-----+     |
|           \  /             |                   |           \  /            |
|            o               |                   |            o              |
|  +------+ /                |                   |  +------+ /               |   +------+
|  |Fwt_Nf|/                 |                   |  |Csw_Nw|/                |---| Sc_* |
|  +------+                  |                   |  +------+                 |   +------+                        
|                            |                   |                           |
|                            |                   |                           |
|  +------+                  |                   |             +--------+    |
|  |Btr_1 |\                 |                   |             | scId_* |----+
|  +------+ \                |                   |             +--------+
|            o               |                   v
|  +------+ / \              |                   Csw_* ordered as they appear in block and transactions
|  |Btr_2 |/   \             |
|  +------+     +------+     |                   
|               | BtMt |-----|                    scTxCommitmentTree UPPER LEVEL STRUCTURE
|   ......      +------+     |                   (bringing together Alive and Ceased subtrees)  
|           \ /              |                   
|            o               |                   |  +------+
|  +------+ /                |                   |  | Sc_1 |
|  |Btr_Nb|/                 |                   |  +------+\
|  +------+                  |   +------+        |           o
|                            |---| Sc_* |        |  +------+/ \
|                            |   +------+        |  | Sc_2 |   \
|  +------+                  |                   |  +------+    +--------------------+
|  |Crt_1 |\                 |                   |              | ScTxCommitmentTree |
|  +------+ \                |                   |              +--------------------+
|            o               |                   |   .....     /
|  +------+ / \              |                   |          \ /
|  |Crt_2 |/   \             |                   |           o
|  +------+     +------+     |                   |  +------+/
|               |CrtMt |-----|                   |  | Sc_N |
|   ......      +------+     |                   |  +------+
|           \ /              |                   |
|            o               |                   v     
|  +------+ /                |                   Sc_* ordered by scId     
|  |Crt_Nc|/                 |         
|  +------+                  |         Nomenclature:
|                            |          Fwt_*  -> forward transfer output data
|                            |          Btr_*  -> backward transfer requests output data
|  +------+                  |          Crt_*  -> certificates data
|  |ScC_* |------------------|          ScC_*  -> sidechain creation output data
|  +------+                  |          Csw_*  -> ceased sidechain input data
|                            |          scId_* -> sidechain identifier
|                            |          *Mt    -> Merkle tree root of the Merkle trees described aside               
|              +--------+    |          Sc_*   -> for Alive Sidechain subtree, PoseidonHash(FtMt | BtMt | CertMt | scId_*)       
|              | scId_* |----+                 -> for Ceased Sidechain subtree, PoseidonHash(CswMt | scId_*)
|              +--------+
v
Fwt_*, Btr_*, Crt_* and ScC_* each ordered
as they appear in block and transactions
```

## Compilation notes
Picked branch sc_tx_commitment from SDK. It uses ad-hoc jar from zendoo_sc_cryptolib, got from Sasha via telegram. Some failing tests, under control  
In zendoo-sc-cryptolib branch where PoseidonHash related changes have been implemented is updatable_poseidon. rustc/cargo v 1.40.0 won't compile. Update to 1.47.0 would do with minor warnings. cargo fmt not called, would modify several files  
Imported on eclipse via File --> Import --> Maven --> Existing Maven Project --> Browse to root dir --> ok ok  
Eclipse plugin for Rust is called Corrosion: Help --> Eclipse Marketplace --> Search for Corrosion and install. To be tested

## Next steps
Another operation which cross chain transfer protocol requires is proof verification. Proofs are created in SC and in MC UTs and verified in MC and in SC UTs.  
Currently proof verification functions are not absorbed into zendoo-CCTP-lib and belong to mc_cryto_lib. However in next future we could move them and get an library inclusion flow as follows:  

    +-------+ginger-lib+------+
    |            +            |
    |            |            |
    |            v            |
    |     zendoo-CCTP-lib     |
    |            +            |
    |            |            |
    |            v            |
    +-> zendoo-sc-cryptolib <-+

We should be able to do it since there are currently no crosschain related functionalities which belong to mainchain and not sidechain.  
(Daniele) possibly remove forwarding functions, so to eliminate inclusion of ginger-lib from mc/zendoo-sc-cryptolib and just include zendoo-CCTP-lib from zendoo-sc-cryptolib

