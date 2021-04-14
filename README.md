# zendoo-cctp-lib

## Design indications
* Both certificate proofs and csw proofs can be batched altogether.
* Upon batch verification failure, mainchain does not necessarily need to re-verify. E.g. in block connection a batched failure is enough drop the block without need to find the offending proofs; on the contrary on txes/certs mempool processing mainchain needs to find exactly the offending and the valid txes/certs.
* The whole verification process will be made of two steps:
  - Load phase, where all proofs inputs from several certificates/transactions are collected and stored.
  - BatchVerify phase, where data collected are verified.
*  It's up to Mainchain to initiate the Load phase and also to indicate where collected data will be dropped, taking lower layers to a blank state again, ready for a new, different validation.
*  It's up to Mainchain to specify what txes/certs among the loaded ones will be batched verified. In other word, it is up to Mainchain to decide if a re-validation should be attempted and which exact txes/certs will participate the re-validation.


## Interface
Mainchain should be provided with the folliwing interface:
```
LoadCertificateData(/*key*/certHash, )

```
