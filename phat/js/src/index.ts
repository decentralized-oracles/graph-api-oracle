// *** YOU ARE LIMITED TO THE FOLLOWING IMPORTS TO BUILD YOUR PHAT CONTRACT     ***
// *** ADDING ANY IMPORTS WILL RESULT IN ERRORS & UPLOADING YOUR CODE TO PHALA  ***
// *** NETWORK WILL FAIL. IF YOU WANT TO KNOW MORE, JOIN OUR DISCORD TO SPEAK   ***
// *** WITH THE PHALA TEAM AT https://discord.gg/5HfmWQNX THANK YOU             ***
import "@phala/pink-env";
import {
  createStructDecoder,
  createStructEncoder,
  decodeStr,
  encodeStr,
  encodeU64,
  encodeU128,
  variant,
  WalkerImpl,
} from "@scale-codec/core";

type HexString = `0x${string}`

type Input = {
  dappId: string,
}

const decodeInput = createStructDecoder<Input>([
  ['dappId', decodeStr],
]);


type Output = {
  dappId: string,
  response_value: DAppStats
}

type DAppStats = {
  developerAddress: string;
  nbStakers: bigint;
  totalStake: bigint;
}

const encodeDAppStats = createStructEncoder<DAppStats>([
  ['developerAddress', encodeStr],
  ['nbStakers', encodeU64],
  ['totalStake', encodeU128],
]);

const encodeOutput = createStructEncoder<Output>([
  ['dappId', encodeStr],
  ['response_value', encodeDAppStats],
]);

enum Error {
  FailedToFetchData = "FailedToFetchData",
  FailedToDecode = "FailedToDecode",
}

function isHexString(str: string): boolean {
  const regex = /^0x[0-9a-f]+$/;
  return regex.test(str.toLowerCase());
}

function stringToHex(str: string): string {
  var hex = "";
  for (var i = 0; i < str.length; i++) {
    hex += str.charCodeAt(i).toString(16);
  }
  return "0x" + hex;
}

function fetchDappStakingStats(graphApi: string, dappId: string): any {

  let queryDappId;
  if (dappId.length == 40){
    queryDappId = "0x" + dappId;
  } else {
    queryDappId = dappId;
  }



  let headers = {
    "Content-Type": "application/json",
    "User-Agent": "phat-contract",
  };
  let query = JSON.stringify({
    query: `query{
                  dApps (
                    filter: {
                      id: {
                        inInsensitive: [\"${queryDappId}\"]
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


function parseInput(hexx: string): Input {
  let hex = hexx.toString();
  if (!isHexString(hex)) {
    throw Error.FailedToDecode;
  }
  hex = hex.slice(2);

  let arr = new Array<number>();
  let i = 0;

  for (let c = 0; c < hex.length; c += 2) {
    arr[i++] = parseInt(hex.substring(c, c + 2), 16);
  }

  let input = WalkerImpl.decode(new Uint8Array(arr), decodeInput);

  return input;
}

function formatOutput(output: Output): Uint8Array {

  const encodedOutput = WalkerImpl.encode(output, encodeOutput);
  console.log("encodedOutput:", encodedOutput);

  return encodedOutput;
}


//
// Here is what you need to implemented for Phat Function, you can customize your logic with
// JavaScript here.
//
// The function will be called with two parameters:
//
// - request: The raw payload from the contract call `request`.
//            In this example, it's a struct with the dAppId: { dappId }
// - settings: The custom settings you set with the `config_core` function of the Action Offchain Rollup Phat Contract.
//            In this example, it's just a simple text of the graph api url.
//
// Your returns value MUST be a Uint8Array, and it will send to your contract directly.
export default function main(request: HexString, settings: string): Uint8Array {

  console.log(`handle req: ${request}`);
  console.log(`settings: ${settings}`);

  let input = parseInput(request);
  const graphApi = settings;
  const dappId = input.dappId;

  console.log(`Request received for dApp ${dappId}`);
  console.log(`Query endpoint ${graphApi}`);

  try {
    const respData = fetchDappStakingStats(graphApi, dappId);
    let dApp = respData.data.dApps.nodes[0];

    const stats: DAppStats = {
      developerAddress: dApp.accountId,
      nbStakers: BigInt(dApp.stakes.totalCount),
      totalStake: BigInt(parseFloat(dApp.stakes.aggregates.sum.totalStake)),
    }

    const output: Output = {
      dappId: dappId,
      //response_value: variant("Some", stats),
      response_value: stats,
      //error: variant('None'),
    }

    console.log(`output - dappId: ${output.dappId}`);
    console.log(`output - developerAddress: ${stats.developerAddress}`);
    console.log(`output - nbStakers: ${stats.nbStakers}`);
    console.log(`output - totalStake: ${stats.totalStake}`);

    return formatOutput(output);
  } catch (error) {
    console.log("error:", error);
    throw error;
    /*
    if (error === Error.FailedToFetchData) {
      throw error;
    } else {
      // otherwise tell client we cannot process it
      console.log("error:", error);

      const output: Output = {
        resp_type: 2,
        dappId: dappId,
        error: variant("Some", errorToCode(error as Error)),
        response_value: variant("None"),
      }

      console.log("3");
      return formatOutput(output);
    }
     */
  }
}
