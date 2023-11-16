# Graph API Oracle

Implements a simple Graph API Oracle with Ink! Offchain Rollup and phat_js.
It supports :
 - Run a js code to query the data from a graph indexer (subsquid or subquery by example) 
 - Push the data into the Ink! Smart Contract.


## Build

To build the contract:

```bash
cargo contract build
```

## Run Unit tests

To run the unit tests:

```bash
cargo test
```

## Run Integration tests

Unfortunately, the cross contract call doesn't work in a local environment.
It means the JS contract used to compute the random value can not been reached and the integration tests can not be run for the time being.  
