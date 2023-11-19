# JS Offchain Rollup

The JS Offchain Rollup is your one-stop solution to connect any API to your ink! smart contract. 

This phat contract empowers you to initiate the data request from the ink! smart contract side. 
The request is then seamlessly sent to your js script for processing. 
You have the liberty to call any APIs to fulfill the request and define the response data structure that will be replied to your ink! smart contract.

Here some example :
 - Graph API Oracle: [../js/artifacts/graph_api_oracle.ts](../js/artifacts/graph_api_oracle.ts)

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
