# zendoo-cctp-lib

## Design indications
* Both certificate proofs and csw proofs can be batched altogether
* Upon batch verification failure, mainchain does not necessarily need to re-verify. E.g. in block connection a batched failure is enough drop the block without need to find the specific failing proofs; on the contrary on txes/certs mempool processing mainchain needs to find exactly the offending and the valid txes/certs.
* 
