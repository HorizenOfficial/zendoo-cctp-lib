<h1 align="center">zendoo-cctp-lib</h1>
<p align="center">
    <a href= "https://github.com/HorizenOfficial/zendoo-cctp-lib/releases"><img src="https://img.shields.io/github/release/HorizenOfficial/zendoo-cctp-lib.svg"></a>
    <a href="AUTHORS"><img src="https://img.shields.io/github/contributors/HorizenOfficial/zendoo-cctp-lib.svg?"></a>
    <a href="https://travis-ci.com/github/HorizenOfficial/zendoo-cctp-lib"><img src="https://app.travis-ci.com/HorizenOfficial/zendoo-cctp-lib.svg?branch=master"></a>
    <a href="LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
    <a href="CONTRIBUTING.md"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square"></a>
</p>


`zendoo-cctp-lib` exposes all the common Rust crypto components and data structures needed to support [Zendoo](https://eprint.iacr.org/2020/123.pdf "Zendoo") in Mainchain and Sidechain.

In particular it exposes interfaces to:

* build and compute the root of the *BitVectorTree* (as described in Appendix A of the [Zendoo](https://eprint.iacr.org/2020/123.pdf "Zendoo") paper)
  starting from the *BitVector* itself, with additional compression/decompression capabilities allowing its cheap inclusion into Mainchain and Sidechain transactions
* build the *SCTxsCommitmentTree*, as described in section 4.1.3 of the [Zendoo](https://eprint.iacr.org/2020/123.pdf "Zendoo") paper, with additional functions to compute proofs of sidechain existence/absence
* verify a single or a batch of Zendoo SNARK proofs related to backward transfer *certificates* and *ceased sidechain withdrawals* transactions. We provide support for verifying ([*Coboundary Marlin*](https://github.com/HorizenLabs/marlin))
proofs, our Marlin variant, and *Final Darlin* proofs, the proving system used in the last step of our recursive PCD scheme (See [HGB](https://eprint.iacr.org/2021/930) for details)
* generate and manage the DLOG verifier keys needed for the verification of such SNARK proofs

**Please note: the code is in development. No guarantees are provided about its security and functionality**

## Build guide

The library compiles on the `stable` toolchain of the Rust compiler. To install Rust, first install `rustup` by following the instructions [here](https://rustup.rs/), or via your platform's package manager.
After that, use `cargo`, the standard Rust build tool, to build the library:

```bash
git clone https://github.com/HorizenOfficial/zendoo-cctp-lib.git
cd zendoo-cctp-lib
cargo build --release
```

This library comes with unit tests for each of the provided crates. Run the tests with:

```bash
cargo test --all-features
```

More detailed build guide can be found in in our [build guide](BUILD.md).
