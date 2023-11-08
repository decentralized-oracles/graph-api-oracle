# Graph Api Oracle with Ink! Smart Contract (on Astar Network) and Ink! Phat Contract (on Phala Network)

Scenario described here in the communication betwen Ink! Smart Contract on Astar Network and Ink! Phat Contract on Phala Network:
1) The Phat Contract `GraphApiOracle` (on Phala Network) queries the data from a graph api (subsquid, subquery or graph) and push the data into the Smart Contract `GraphApiConsumer` (on Astar Network)
2) The Smart Contract `GraphApiConsumer` (on Astar Network) verifies the data used by the Phat Contract `GraphApiOracle` and saves the data to be displayed in the UI 

You can find a demo here: TODO

The Phat Contract and Ink! Smart Contract have been built with the Phat Offchain Rollup.
The full documentation of this SDK can be found here: https://github.com/Phala-Network/phat-offchain-rollup


## Phat Contract `GraphApiOracle`

To deploy this Phat Contract you can build the contract or use existing artifacts

More information here: [phat/contracts/graph_api_oracle/README.md](phat/contracts/graph_api_oracle/README.md)

### Build the contract

To build the contract:
```bash
cd phat/contracts/graph_api_oracle
cargo contract build
```

### Use existing artifacts
All artifacts are here: [phat/artifacts](phat/artifacts)


## Ink! Smart Contract `GraphApiConsumer`

To deploy this Ink! Smart Contract you can build the contract or use existing artifacts

More information here: [ink/contracts/graph_api_consumer/README.md](ink/contracts/graph_api_consumer/README.md)

### Build the contract

To build the contract:
```bash
cd ink/contracts/graph_api_consumer
cargo contract build
```

### Use existing artifacts
All artifacts are here: [ink/artifacts](ink/artifacts)



## Configure the target contract in the Phat Contract `GraphApiOracle`
You have to configure the rpc, the pallet id, the call id and the contract id to call the Smart Contract `GraphApiConsumer`.

For example:
```
RPC=https://shibuya.public.blastapi.io
PALLET_ID=70
CALL_ID=6
#public key of the contract aesULxtrttD4VGe1oDWGnDihbknjQ44GYwN1L8RXMcWZxis
CONTRACT_ID=0xd0a5af9b2cd1fa7ca7b8c37cb1323b6596c7810b661085dbc32bdcd3a498219c
```

![config_target_contract](https://github.com/GuiGou12358/decentralized_oracle-graph-api-oracle/assets/92046056/aef288ae-3f8d-4c52-a92b-170c9ab20340)

#### Enable Meta-Tx

Meta transaction allows the Phat Contract to submit rollup tx with attest key signature while using arbitrary account to pay the gas fee. 
To enable meta tx in the unit test you have to set the private key

For example, the private key of account //bob: 0x398f0c28f98885e046333d4a41c19cee4c37368a9832c6502f6cfd182e2aef89

If you don't use Meta-Tx, you have to be sure that address of Phat Contract `GraphApiOracle` will be able to pay transaction fees on Astar Network.

## Configure the graph api in the Phat Contract `GraphApiOracle`

You have to configure the http endpoint to reach to query the data.

![image](https://github.com/GuiGou12358/decentralized_oracle-graph-api-oracle/assets/92046056/47aaddf7-267f-4259-9f87-970cab903cca)

![image](https://github.com/GuiGou12358/decentralized_oracle-graph-api-oracle/assets/92046056/5e2557fc-f32b-45b0-a53e-46cf1a14154e)

## Configure the js used to query the data in the Phat Contract `GraphApiOracle`

You have to configure the js source code that will run inside the crate phat::js.
The graph api endoing configured above will be given in parameter in the main method of js code.
All data comming from the Ink! Smart Contract `GraphApiConsumer` will be also given in parameters. 

![image](https://github.com/GuiGou12358/decentralized_oracle-graph-api-oracle/assets/92046056/99ce49cb-7e67-4b9a-8c1a-d88a69231742)

![image](https://github.com/GuiGou12358/decentralized_oracle-graph-api-oracle/assets/92046056/29935b5f-5ee4-4747-bbce-e93260ea3038)

## Grant the attestor in the Smart Contract `GraphApiConsumer`
You have to grant the Phat Contract `GraphApiOracle` as attestor in the Smart Contract `GraphApiConsumer`.

If you use the Meta-Tx, you have to grant the ecdsa address.

![get_attest_address](https://github.com/GuiGou12358/decentralized_oracle-graph-api-oracle/assets/92046056/2bda019b-5af3-4bf7-bd0a-c26f91761181)

If you don't use the Meta-Tx, you have to grant the sr25519 public key.

![get_attest_ecdsa_address](https://github.com/GuiGou12358/decentralized_oracle-graph-api-oracle/assets/92046056/1b87935d-36d7-459c-a42a-e1e13b91e24f)

And grant the Phat Contract as attestor 

![image](https://github.com/GuiGou12358/decentralized_oracle-graph-api-oracle/assets/92046056/f4b03e5d-0b89-428f-9257-03ec18e9a3af)

### Register the code hash used to query the data

In the Smart Contract `GraphApiConsumer`, you have to register the hash of the source code used to query the data by the Phat Contract `GraphApiOracle`.

![Capture](https://github.com/GuiGou12358/decentralized_oracle-graph-api-oracle/assets/92046056/7f91b067-a172-4812-9e24-c58f7a3a6b1e)

![image](https://github.com/GuiGou12358/decentralized_oracle-graph-api-oracle/assets/92046056/418ae2d4-3008-4cae-9c7f-7baa2b2048cb)

## Test

### Phat Contract `GraphApiOracle` - Push the data into `GraphApiConsumer`

Query the data from the graph api and push them into the Smart Contract `GraphApiConsumer`.

![image](https://github.com/GuiGou12358/decentralized_oracle-graph-api-oracle/assets/92046056/67fd24f3-1cdf-432d-ac65-d59655d0d7c5)

![image](https://github.com/GuiGou12358/decentralized_oracle-graph-api-oracle/assets/92046056/29cb83f1-c866-4534-ac55-e1eb22385731)

In result you have the transaction id.

![image](https://github.com/GuiGou12358/decentralized_oracle-graph-api-oracle/assets/92046056/33a500fe-8586-4c73-9948-8c3f16ffc394)

### Ink! Smart Contract `GraphApiConsumer` - Read the data coming from `GraphApiOracle`

![image](https://github.com/GuiGou12358/decentralized_oracle-graph-api-oracle/assets/92046056/96465498-4644-4705-84e2-c345389079c2)


