# Graph API Consumer

Implements a simple oracle to get/display data query from a graph indexer (subquery, subsquid by example).
Here we will display the data linked to the Astar dApp Staking.

It uses the crate `phat_rollup_anchor_ink`.

It supports:
 - configure the attestor(s) authorized to send the data. Only an address granted as `MANAGER` can do it.
 - handle the messages containing the data. Only an address granted as `ATTESTOR` can do it.
 - display the last value received for a given dApp.
 - allow meta transactions to separate the attestor and the payer.
 - managed the roles and grant an address as `ADMIN`, `MANAGER`, `ATTESTOR`. Only the admin can do it.

By default, the contract owner is granted as `ADMIN` and `MANAGER` but it is not granted as `ATTESTOR`.

## Build

To build the contract:

```bash
cargo contract build
```

## Run e2e tests

Before you can run the test, you have to install a Substrate node with pallet-contracts. By default, `e2e tests` require that you install `substrate-contracts-node`. You do not need to run it in the background since the node is started for each test independently. To install the latest version:
```bash
cargo install contracts-node --git https://github.com/paritytech/substrate-contracts-node.git
```

If you want to run any other node with pallet-contracts you need to change `CONTRACTS_NODE` environment variable:
```bash
export CONTRACTS_NODE="YOUR_CONTRACTS_NODE_PATH"
```

And finally execute the following command to start e2e tests execution.
```bash
cargo test --features e2e-tests
```
