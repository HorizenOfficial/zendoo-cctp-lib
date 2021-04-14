# zendoo-cctp-lib: Batch Verifier Interface

## Basic facts, shaping design decisions
* Both certificate proofs and csw proofs can be batched altogether.
* Upon batch verification failure, mainchain does not necessarily need to re-verify. E.g. in block connection a batched failure is enough drop the block without need to find the offending proofs; on the contrary on txes/certs mempool processing mainchain needs to find exactly the offending and the valid txes/certs.
* Upon batch verification failure, prover can provide some best-effort information, but won't be necessarily able to indicate the offending proofs in the batch.
* The whole verification process will be made of three steps:
  - Load phase, where all proofs inputs from several certificates/transactions are collected and stored.
  - BatchVerify phase, where data collected are verified. Mainchain is allowed to run this phase as many times as needed, on any subset of loaded inputs.
  - ClearUp phase, dropping all collected data and ensuring no side-effects on next cycle.
*  It's up to Mainchain to initiate the Load phase and also to indicate where collected data will be dropped, taking lower layers to a blank state again, ready for a new, different validation.
*  It's up to Mainchain to specify what txes/certs among the loaded ones will be batched verified. In other word, it is up to Mainchain to decide if a re-validation should be attempted and which exact txes/certs will participate the re-validation.


## Tentative Interface
Mainchain should be provided with the folliwing interface \[CURRENTLY PSEUDOCODE, TO BE SPECIFIED\]:
```
LoadCertificateData(/*key*/certHash, /*value*/ CertificateProofInputsStruct) --> bool
LoadCswData(/*key*/pair<txHash, inputPos>, /*value*/ CswProofInputsStruct)   --> bool
/*Note: Unlike certs, csw have one proof per input, hence the key is a TxHash,inputPos pair*/
ClearData()                                                                  --> void /*drop all data loaded before*/

BatchVerify()            --> bool True/False if batch verification works correctly or not. In case of failure some diagnostic may be retrieved via <TO BE CONFIRMED>
BatchVerify(tuple<Keys>) --> bool True/False if batch verification works correctly ON THE VALUES CORRESPONDING ON SPECIFIED KEYS ONLY or not. In case of failure some diagnostic may be retrieved via <TO BE CONFIRMED>

```

## Open points
* Establish the layout for CertificateProofInputsStruct and CswProofInputsStruct. Maybe they do not even exist and we will pass each proof input as parameter, similarly to what we did for scTxCommitmentTree
* Establish which layer will be responsible of mapping CertificateProofInputsStruct and CswProofInputsStruct to field elements
* Handle edge cases like calls to BatchVerify() without loaded data or re-insertions of data 
