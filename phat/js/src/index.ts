// *** YOU ARE LIMITED TO THE FOLLOWING IMPORTS TO BUILD YOUR PHAT CONTRACT     ***
// *** ADDING ANY IMPORTS WILL RESULT IN ERRORS & UPLOADING YOUR CODE TO PHALA  ***
// *** NETWORK WILL FAIL. IF YOU WANT TO KNOW MORE, JOIN OUR DISCORD TO SPEAK   ***
// *** WITH THE PHALA TEAM AT https://discord.gg/5HfmWQNX THANK YOU             ***
import "@phala/pink-env";

enum Error {
  BadLensProfileId = "BadLensProfileId",
  FailedToFetchData = "FailedToFetchData",
  FailedToDecode = "FailedToDecode",
  MalformedRequest = "MalformedRequest",
}

function errorToCode(error: Error): number {
  switch (error) {
    case Error.BadLensProfileId:
      return 1;
    case Error.FailedToFetchData:
      return 2;
    case Error.FailedToDecode:
      return 3;
    case Error.MalformedRequest:
      return 4;
    default:
      return 0;
  }
}


function stringToHex(str: string): string {
  var hex = "";
  for (var i = 0; i < str.length; i++) {
    hex += str.charCodeAt(i).toString(16);
  }
  return "0x" + hex;
}

function fetchDappStakingStats(graphApi: string, dappId: string): any {
  // dappId should be like 0x0001
  let headers = {
    "Content-Type": "application/json",
    "User-Agent": "phat-contract",
  };
  let query = JSON.stringify({
    query: `query{
                  dApps (
                    filter: {
                      id: {
                        inInsensitive: [\"${dappId}\"]
                      }
                    }
                  ){
                    nodes {
                      id
                      accountId
                      registered
                      stakes (
                        filter: { totalStake : {notEqualTo: \"0\"} }
                      ){
                        totalCount
                        aggregates{ sum {totalStake} }
                      }
                    }
                  }
                }`,
  });

  let body = stringToHex(query);
  //
  // In Phat Function runtime, we not support async/await, you need use `pink.batchHttpRequest` to
  // send http request. The function will return an array of response.
  //
  let response = pink.batchHttpRequest(
      [
        {
          url: graphApi,
          method: "POST",
          headers,
          body,
          returnTextBody: true,
        },
      ],
      10000
  )[0];

  if (response.statusCode !== 200) {
    console.log(
        `Fail to read Graph api with status code: ${response.statusCode}, error: ${
            response.error || response.body
        }}`
    );
    throw Error.FailedToFetchData;
  }
  let respBody = response.body;
  if (typeof respBody !== "string") {
    throw Error.FailedToDecode;
  }
  return JSON.parse(respBody);
}


//
// Here is what you need to implemented for Phat Function, you can customize your logic with
// JavaScript here.
//
// The function will be called with two parameters:
//
// - request: The raw payload from the contract call `request` (check the `request` function in TestLensApiConsumerConract.sol).
//            In this example, it's a tuple of two elements: [requestId, profileId]
// - settings: The custom settings you set with the `config_core` function of the Action Offchain Rollup Phat Contract. In
//            this example, it just a simple text of the lens api url prefix.
//
// Your returns value MUST be a hex string, and it will send to your contract directly. Check the `_onMessageReceived` function in
// TestLensApiConsumerContract.sol for more details. We suggest a tuple of three elements: [successOrNotFlag, requestId, data] as
// the return value.
//
export default function main(graphApi: string, dappId: string): string {
  // TODO parse the request from ink! smart contract
  console.log(`Request received for dApp ${dappId}`);
  console.log(`Query endpoint ${graphApi}`);

  try {
    const respData = fetchDappStakingStats(graphApi, dappId);
    let dApp = respData.data.dApps.nodes[0];
    let stats = JSON.stringify({
      dAppId: dappId,
      developerAddress: dApp.accountId,
      nbStakers : dApp.stakes.totalCount,
      totalStake : dApp.stakes.aggregates.sum.totalStake,
    });
    console.log("stats:", stats);
    return stats;
  } catch (error) {
    if (error === Error.FailedToFetchData) {
      throw error;
    } else {
      // otherwise tell client we cannot process it
      console.log("error:", error);
      return "Error"; //TODO
    }
  }
}