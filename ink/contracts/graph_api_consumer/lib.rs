#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[openbrush::implementation(Ownable, AccessControl, Upgradeable)]
#[openbrush::contract]
pub mod graph_api_consumer {
    use ink::codegen::{EmitEvent, Env};
    use ink::env::hash::{Blake2x256, HashOutput};
    use ink::prelude::vec::Vec;
    use ink::storage::{Lazy, Mapping};
    use openbrush::contracts::access_control::*;
    use openbrush::contracts::ownable::*;
    use openbrush::traits::Storage;
    use scale::{Decode, Encode};

    use phat_rollup_anchor_ink::traits::{
        meta_transaction, meta_transaction::*, rollup_anchor, rollup_anchor::*,
    };

    type CodeHash = [u8; 32];
    pub const MANAGER_ROLE: RoleType = ink::selector_id!("MANAGER_ROLE");

    /// Events emitted when a random value is requested
    #[ink(event)]
    pub struct RandomValueRequested {
        /// id of the requestor
        requestor_id: AccountId,
        /// nonce of the requestor
        requestor_nonce: u128,
        /// minimum value requested
        min: u128,
        /// maximum value requested
        max: u128,
        /// when the value has been requested
        timestamp: u64,
    }

    /// Events emitted when a random value is received
    #[ink(event)]
    pub struct RandomValueReceived {
        /// id of the requestor
        requestor_id: AccountId,
        /// nonce of the requestor
        requestor_nonce: u128,
        /// random_value
        random_value: u128,
        /// when the value has been received
        timestamp: u64,
    }

    /// Events emitted when an error is received
    #[ink(event)]
    pub struct ErrorReceived {
        /// id of the requestor
        requestor_id: AccountId,
        /// nonce of the requestor
        requestor_nonce: u128,
        /// error number
        err_no: Vec<u8>,
        /// when the error has been received
        timestamp: u64,
    }

    /// Errors occurred in the contract
    #[derive(Encode, Decode, Debug)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum ContractError {
        AccessControlError(AccessControlError),
        RollupAnchorError(RollupAnchorError),
        MetaTransactionError(MetaTransactionError),
        FailedToDecode,
        IncorrectMinMaxValues,
    }

    /// convertor from MessageQueueError to ContractError
    impl From<AccessControlError> for ContractError {
        fn from(error: AccessControlError) -> Self {
            ContractError::AccessControlError(error)
        }
    }
    /// convertor from RollupAnchorError to ContractError
    impl From<RollupAnchorError> for ContractError {
        fn from(error: RollupAnchorError) -> Self {
            ContractError::RollupAnchorError(error)
        }
    }
    /// convertor from MetaTxError to ContractError
    impl From<MetaTransactionError> for ContractError {
        fn from(error: MetaTransactionError) -> Self {
            ContractError::MetaTransactionError(error)
        }
    }

    /// Type of response when the offchain rollup communicates with this contract
    const TYPE_ERROR: u8 = 0;
    const TYPE_RESPONSE: u8 = 10;

    /// Message to request the random value
    /// message pushed in the queue by the Ink! smart contract and read by the offchain rollup
    #[derive(Eq, PartialEq, Clone, scale::Encode, scale::Decode)]
    struct RandomValueRequestMessage {
        /// id of the requestor
        requestor_id: AccountId,
        /// nonce of the requestor
        requestor_nonce: u128,
        /// minimum value requested
        min: u128,
        /// maximum value requested
        max: u128,
    }
    /// Message sent to provide a random value
    /// response pushed in the queue by the offchain rollup and read by the Ink! smart contract
    #[derive(Encode, Decode)]
    struct RandomValueResponseMessage {
        /// Type of response
        resp_type: u8,
        /// initial request
        request: RandomValueRequestMessage,
        /// hash of js script executed to calculate the random value
        js_script_hash: Option<CodeHash>,
        /// random_value
        random_value: Option<u128>,
        /// when an error occurs
        error: Option<Vec<u8>>,
    }


    #[ink(storage)]
    #[derive(Default, Storage)]
    pub struct GraphApiOracleClient {
        #[storage_field]
        ownable: ownable::Data,
        #[storage_field]
        access: access_control::Data,
        #[storage_field]
        rollup_anchor: rollup_anchor::Data,
        #[storage_field]
        meta_transaction: meta_transaction::Data,
        /// Nonce of the requestor.
        requestor_nonces: Mapping<AccountId, Nonce>,
        /// hash of the request by (requestor,nonce)
        hash_requests: Mapping<(AccountId, Nonce), Hash>,
        /// last random values by requestor
        /// The key contains the requestor address
        /// the value contains the tuple (timestamp, random_value)
        last_values: Mapping<AccountId, (u64, u128)>,
        /// hash of js script executed to calculate the random value
        js_script_hash: Lazy<CodeHash>,
    }

    impl GraphApiOracleClient {
        #[ink(constructor)]
        pub fn new() -> Self {
            let mut instance = Self::default();
            let caller = instance.env().caller();
            // set the owner of this contract
            ownable::Internal::_init_with_owner(&mut instance, caller);
            // set the admin of this contract
            access_control::Internal::_init_with_admin(&mut instance, Some(caller));
            // grant the role manager
            AccessControl::grant_role(&mut instance, MANAGER_ROLE, Some(caller))
                .expect("Should grant the role MANAGER_ROLE");
            instance
        }

        #[ink(message)]
        #[openbrush::modifiers(access_control::only_role(MANAGER_ROLE))]
        pub fn get_requestor_nonce(
            &mut self,
            requestor: AccountId,
        ) -> Result<Nonce, ContractError> {
            let nonce = self.requestor_nonces.get(requestor).unwrap_or(0);
            Ok(nonce)
        }

        #[ink(message)]
        pub fn get_last_value(&mut self) -> Result<Option<(u64, u128)>, ContractError> {
            let requestor = self.env().caller();
            let value = self.last_values.get(requestor);
            Ok(value)
        }

        #[ink(message)]
        pub fn request_random_value(
            &mut self,
            min: u128,
            max: u128,
        ) -> Result<QueueIndex, ContractError> {

            if min > max {
                return Err(ContractError::IncorrectMinMaxValues);
            }

            let requestor_id = self.env().caller();
            // get the current nonce
            let requestor_nonce = self.requestor_nonces.get(requestor_id).unwrap_or(0);
            // increment the nonce
            let requestor_nonce = requestor_nonce + 1;

            // push the message in the queue
            let message = RandomValueRequestMessage {
                requestor_id,
                requestor_nonce,
                min,
                max,
            };
            let message_id = self.push_message(&message)?;

            // hash the message
            let mut hash = <Blake2x256 as HashOutput>::Type::default();
            ink::env::hash_encoded::<Blake2x256, _>(&message, &mut hash);
            // save the hash
            let hash: Hash = hash.into();
            self.hash_requests
                .insert((requestor_id, &requestor_nonce), &hash);

            // update the nonce
            self.requestor_nonces
                .insert(requestor_id, &requestor_nonce);

            // emmit te event
            self.env().emit_event(RandomValueRequested {
                requestor_id,
                requestor_nonce,
                min,
                max,
                timestamp: self.env().block_timestamp(),
            });

            Ok(message_id)
        }

        #[ink(message)]
        pub fn register_attestor(&mut self, account_id: AccountId) -> Result<(), ContractError> {
            AccessControl::grant_role(self, ATTESTOR_ROLE, Some(account_id))?;
            Ok(())
        }

        #[ink(message)]
        pub fn get_attestor_role(&self) -> RoleType {
            ATTESTOR_ROLE
        }

        #[ink(message)]
        pub fn get_manager_role(&self) -> RoleType {
            MANAGER_ROLE
        }

        #[ink(message)]
        #[openbrush::modifiers(access_control::only_role(MANAGER_ROLE))]
        pub fn set_js_script_hash(&mut self, js_script_hash: CodeHash) -> Result<(), ContractError> {
            self.js_script_hash.set(&js_script_hash);
            Ok(())
        }

        #[ink(message)]
        pub fn get_js_script_hash(&self) -> Option<CodeHash> {
            self.js_script_hash.get()
        }

    }

    impl RollupAnchor for GraphApiOracleClient {}
    impl MetaTransaction for GraphApiOracleClient {}

    impl rollup_anchor::MessageHandler for GraphApiOracleClient {
        fn on_message_received(&mut self, action: Vec<u8>) -> Result<(), RollupAnchorError> {
            // parse the response
            let message: RandomValueResponseMessage =
                Decode::decode(&mut &action[..]).or(Err(RollupAnchorError::FailedToDecode))?;

            let requestor_id = message.request.requestor_id;
            let requestor_nonce = message.request.requestor_nonce;

            // hash the message
            let mut hash = <Blake2x256 as HashOutput>::Type::default();
            ink::env::hash_encoded::<Blake2x256, _>(&message.request, &mut hash);
            let hash: Hash = hash.into();
            let expected_hash = self
                .hash_requests
                .get((requestor_id, &requestor_nonce))
                .ok_or(RollupAnchorError::ConditionNotMet)?; // improve the error

            // check the hash
            if hash != expected_hash {
                return Err(RollupAnchorError::ConditionNotMet); // improve the error
            }
            // remove the ongoing hash
            self.hash_requests.remove((requestor_id, &requestor_nonce));

            // check the js code hash
            let expected_js_hash = self
                .js_script_hash
                .get()
                .ok_or(RollupAnchorError::ConditionNotMet)?; // improve the error

            let used_js_hash = message
                .js_script_hash
                .ok_or(RollupAnchorError::ConditionNotMet)?; // improve the error
            // check the js code hash
            if used_js_hash != expected_js_hash {
                return Err(RollupAnchorError::ConditionNotMet); // improve the error
            }

            let timestamp = self.env().block_timestamp();

            // handle the response
            if message.resp_type == TYPE_RESPONSE {
                // we received the random value
                // TODO check if the random value is right
                let random_value = message
                    .random_value
                    .ok_or(RollupAnchorError::FailedToDecode)?;

                // register the info
                self.last_values.insert(requestor_id, &(timestamp, random_value));

                // emmit te event
                self.env().emit_event(RandomValueReceived {
                    requestor_id,
                    requestor_nonce,
                    random_value,
                    timestamp,
                });
            } else if message.resp_type == TYPE_ERROR {
                // we received an error
                self.env().emit_event(ErrorReceived {
                    requestor_id,
                    requestor_nonce,
                    err_no: message.error.unwrap_or_default(),
                    timestamp,
                });
            } else {
                // response type unknown
                return Err(RollupAnchorError::UnsupportedAction);
            }

            Ok(())
        }
    }

    /// Events emitted when a message is pushed in the queue
    #[ink(event)]
    pub struct MessageQueued {
        pub id: u32,
        pub data: Vec<u8>,
    }

    /// Events emitted when a message is proceed
    #[ink(event)]
    pub struct MessageProcessedTo {
        pub id: u32,
    }

    impl rollup_anchor::EventBroadcaster for GraphApiOracleClient {
        fn emit_event_message_queued(&self, id: u32, data: Vec<u8>) {
            self.env().emit_event(MessageQueued { id, data });
        }

        fn emit_event_message_processed_to(&self, id: u32) {
            self.env().emit_event(MessageProcessedTo { id });
        }
    }

    impl meta_transaction::EventBroadcaster for GraphApiOracleClient {
        fn emit_event_meta_tx_decoded(&self) {
            self.env().emit_event(MetaTxDecoded {});
        }
    }

    /// Events emitted when a meta transaction is decoded
    #[ink(event)]
    pub struct MetaTxDecoded {}

    #[cfg(all(test, feature = "e2e-tests"))]
    mod e2e_tests {
        use super::*;
        use openbrush::contracts::access_control::accesscontrol_external::AccessControl;

        use ink::env::DefaultEnvironment;
        use ink_e2e::subxt::tx::Signer;
        use ink_e2e::{build_message, PolkadotConfig};

        use phat_rollup_anchor_ink::traits::{
            meta_transaction::metatransaction_external::MetaTransaction,
            rollup_anchor::rollupanchor_external::RollupAnchor,
        };

        type E2EResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

        async fn alice_instantiates_contract(
            client: &mut ink_e2e::Client<PolkadotConfig, DefaultEnvironment>,
        ) -> AccountId {
            let constructor = GraphApiOracleClientRef::new();
            client
                .instantiate("graph_api_consumer", &ink_e2e::alice(), constructor, 0, None)
                .await
                .expect("instantiate failed")
                .account_id
        }

        async fn alice_set_js_script_hash(
            client: &mut ink_e2e::Client<PolkadotConfig, DefaultEnvironment>,
            contract_id: &AccountId,
        ) {
            let code_hash = [1u8; 32];
            let set_js_script_hash = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.set_js_script_hash(code_hash));
            client
                .call(&ink_e2e::alice(), set_js_script_hash, 0, None)
                .await
                .expect("set js code hash failed");
        }

        async fn alice_grants_bob_as_attestor(
            client: &mut ink_e2e::Client<PolkadotConfig, DefaultEnvironment>,
            contract_id: &AccountId,
        ) {
            // bob is granted as attestor
            let bob_address = ink::primitives::AccountId::from(ink_e2e::bob().public_key().0);
            let grant_role = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.grant_role(ATTESTOR_ROLE, Some(bob_address)));
            client
                .call(&ink_e2e::alice(), grant_role, 0, None)
                .await
                .expect("grant bob as attestor failed");
        }


        #[ink_e2e::test]
        async fn test_incorrect_min_max_values(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // given
            let contract_id = alice_instantiates_contract(&mut client).await;

            // a price request is sent but min > max
            let request_random_value = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.request_random_value(1000_u128, 100_u128));
            let result = client
                .call(&ink_e2e::charlie(), request_random_value, 0, None)
                .await;

            assert!(result.is_err());

            Ok(())

        }

        #[ink_e2e::test]
        async fn test_receive_reply(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // given
            let contract_id = alice_instantiates_contract(&mut client).await;

            // set the js code hash
            alice_set_js_script_hash(&mut client, &contract_id).await;

            // bob is granted as attestor
            alice_grants_bob_as_attestor(&mut client, &contract_id).await;

            // a price request is sent
            let request_random_value = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.request_random_value(100_u128, 1000_u128));
            let result = client
                .call(&ink_e2e::charlie(), request_random_value, 0, None)
                .await
                .expect("Request price should be sent");
            // event MessageQueued
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            let request_id = result.return_value().expect("Request id not found");

            // then a response is received
            let random_value = Some(131_u128);
            let payload = RandomValueResponseMessage {
                resp_type: TYPE_RESPONSE,
                request: RandomValueRequestMessage {
                    requestor_id: ink::primitives::AccountId::from(
                        ink_e2e::charlie().public_key().0,
                    ),
                    requestor_nonce: 1,
                    min: 100_u128,
                    max: 1000_u128,
                },
                js_script_hash: Some([1u8; 32]),
                random_value,
                error: None,
            };
            let actions = vec![
                HandleActionInput::Reply(payload.encode()),
                HandleActionInput::SetQueueHead(request_id + 1),
            ];
            let rollup_cond_eq = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client
                .call(&ink_e2e::bob(), rollup_cond_eq, 0, None)
                .await
                .expect("rollup cond eq should be ok");
            // two events : MessageProcessedTo and RandomValueReceived
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            // and check if the random value is filled
            let get_last_value = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.get_last_value());
            let get_res = client
                .call_dry_run(&ink_e2e::charlie(), &get_last_value, 0, None)
                .await;
            let last_value = get_res.return_value().expect("Last value not found");

            assert_eq!(last_value.unwrap().1, 131);

            // reply in the future should fail
            let actions = vec![
                HandleActionInput::Reply(payload.encode()),
                HandleActionInput::SetQueueHead(request_id + 2),
            ];
            let rollup_cond_eq = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            assert!(
                result.is_err(),
                "Rollup should fail because we try to pop in the future"
            );

            // reply in the past should fail
            let actions = vec![
                HandleActionInput::Reply(payload.encode()),
                HandleActionInput::SetQueueHead(request_id),
            ];
            let rollup_cond_eq = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            assert!(
                result.is_err(),
                "Rollup should fail because we try to pop in the past"
            );

            Ok(())
        }

        #[ink_e2e::test]
        async fn test_many_sequential_requests_replies(
            mut client: ink_e2e::Client<C, E>,
        ) -> E2EResult<()> {
            // given
            let contract_id = alice_instantiates_contract(&mut client).await;

            // set the js code hash
            alice_set_js_script_hash(&mut client, &contract_id).await;

            // bob is granted as attestor
            alice_grants_bob_as_attestor(&mut client, &contract_id).await;

            // a request is sent
            let request_random_value = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.request_random_value(0_u128, 1000000000_u128));
            let result = client
                .call(&ink_e2e::charlie(), request_random_value, 0, None)
                .await
                .expect("Request random value should be sent");
            // event MessageQueued
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            let request_id = result.return_value().expect("Request id not found");

            // then a response is received
            let random_value = Some(131_u128);
            let payload = RandomValueResponseMessage {
                resp_type: TYPE_RESPONSE,
                request: RandomValueRequestMessage {
                    requestor_id: ink::primitives::AccountId::from(
                        ink_e2e::charlie().public_key().0,
                    ),
                    requestor_nonce: 1,
                    min: 0_u128,
                    max: 1000000000_u128,
                },
                js_script_hash: Some([1u8; 32]),
                random_value,
                error: None,
            };
            let actions = vec![
                HandleActionInput::Reply(payload.encode()),
                HandleActionInput::SetQueueHead(request_id + 1),
            ];
            let rollup_cond_eq = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client
                .call(&ink_e2e::bob(), rollup_cond_eq, 0, None)
                .await
                .expect("rollup cond eq should be ok");
            // two events : MessageProcessedTo and RandomValueReceived
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            // and check if the random value is filled
            let get_last_value = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.get_last_value());
            let get_res = client
                .call_dry_run(&ink_e2e::charlie(), &get_last_value, 0, None)
                .await;
            let last_value = get_res.return_value().expect("Last value not found");

            assert_eq!(last_value.unwrap().1, 131);

            // another request is sent
            let request_random_value = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.request_random_value(50_u128, 100_u128));
            let result = client
                .call(&ink_e2e::charlie(), request_random_value, 0, None)
                .await
                .expect("Request random value should be sent");
            // event MessageQueued
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            let request_id = result.return_value().expect("Request id not found");

            // another response is received
            let random_value = Some(75_u128);
            let payload = RandomValueResponseMessage {
                resp_type: TYPE_RESPONSE,
                request: RandomValueRequestMessage {
                    requestor_id: ink::primitives::AccountId::from(
                        ink_e2e::charlie().public_key().0,
                    ),
                    requestor_nonce: 2,
                    min: 50_u128,
                    max: 100_u128,
                },
                js_script_hash: Some([1u8; 32]),
                random_value,
                error: None,
            };
            let actions = vec![
                HandleActionInput::Reply(payload.encode()),
                HandleActionInput::SetQueueHead(request_id + 1),
            ];
            let rollup_cond_eq = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client
                .call(&ink_e2e::bob(), rollup_cond_eq, 0, None)
                .await
                .expect("rollup cond eq should be ok");
            // two events : MessageProcessedTo and RandomValueReceived
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            // and check if the random value is filled
            let get_last_value = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.get_last_value());
            let get_res = client
                .call_dry_run(&ink_e2e::charlie(), &get_last_value, 0, None)
                .await;
            let last_value = get_res.return_value().expect("Last value not found");

            assert_eq!(last_value.unwrap().1, 75);

            Ok(())
        }

        #[ink_e2e::test]
        async fn test_concurrent_requests_replies(
            mut client: ink_e2e::Client<C, E>,
        ) -> E2EResult<()> {
            // given
            let contract_id = alice_instantiates_contract(&mut client).await;

            // set the js code hash
            alice_set_js_script_hash(&mut client, &contract_id).await;

            // bob is granted as attestor
            alice_grants_bob_as_attestor(&mut client, &contract_id).await;

            // a first request is sent
            let request_random_value = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.request_random_value(0_u128, 1000000000_u128));
            let result = client
                .call(&ink_e2e::charlie(), request_random_value, 0, None)
                .await
                .expect("Request random value should be sent");
            // event MessageQueued
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            let request_id_1 = result.return_value().expect("Request id not found");

            // another request is sent
            let request_random_value = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.request_random_value(0_u128, 50_u128));
            let result = client
                .call(&ink_e2e::charlie(), request_random_value, 0, None)
                .await
                .expect("Request random value should be sent");
            // event MessageQueued
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            let request_id_2 = result.return_value().expect("Request id not found");

            // then a response is received
            let random_value = Some(131_u128);
            let payload = RandomValueResponseMessage {
                resp_type: TYPE_RESPONSE,
                request: RandomValueRequestMessage {
                    requestor_id: ink::primitives::AccountId::from(
                        ink_e2e::charlie().public_key().0,
                    ),
                    requestor_nonce: 1,
                    min: 0_u128,
                    max: 1000000000_u128,
                },
                js_script_hash: Some([1u8; 32]),
                random_value,
                error: None,
            };
            let actions = vec![
                HandleActionInput::Reply(payload.encode()),
                HandleActionInput::SetQueueHead(request_id_1 + 1),
            ];
            let rollup_cond_eq = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client
                .call(&ink_e2e::bob(), rollup_cond_eq, 0, None)
                .await
                .expect("rollup cond eq should be ok");
            // two events : MessageProcessedTo and RandomValueReceived
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            // and check if the random value is filled
            let get_last_value = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.get_last_value());
            let get_res = client
                .call_dry_run(&ink_e2e::charlie(), &get_last_value, 0, None)
                .await;
            let last_value = get_res.return_value().expect("Last value not found");

            assert_eq!(last_value.unwrap().1, 131);

            // another response is received
            let random_value = Some(25_u128);
            let payload = RandomValueResponseMessage {
                resp_type: TYPE_RESPONSE,
                request: RandomValueRequestMessage {
                    requestor_id: ink::primitives::AccountId::from(
                        ink_e2e::charlie().public_key().0,
                    ),
                    requestor_nonce: 2,
                    min: 0_u128,
                    max: 50_u128,
                },
                js_script_hash: Some([1u8; 32]),
                random_value,
                error: None,
            };
            let actions = vec![
                HandleActionInput::Reply(payload.encode()),
                HandleActionInput::SetQueueHead(request_id_2 + 1),
            ];
            let rollup_cond_eq = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client
                .call(&ink_e2e::bob(), rollup_cond_eq, 0, None)
                .await
                .expect("rollup cond eq should be ok");
            // two events : MessageProcessedTo and RandomValueReceived
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            // and check if the random value is filled
            let get_last_value = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.get_last_value());
            let get_res = client
                .call_dry_run(&ink_e2e::charlie(), &get_last_value, 0, None)
                .await;
            let last_value = get_res.return_value().expect("Last value not found");

            assert_eq!(last_value.unwrap().1, 25);

            Ok(())
        }

        #[ink_e2e::test]
        async fn test_bad_hash(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // given
            let contract_id = alice_instantiates_contract(&mut client).await;

            // set the js code hash
            alice_set_js_script_hash(&mut client, &contract_id).await;

            // bob is granted as attestor
            alice_grants_bob_as_attestor(&mut client, &contract_id).await;

            // a request is sent
            let request_random_value = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.request_random_value(0_u128, 1000000000_u128));
            let result = client
                .call(&ink_e2e::charlie(), request_random_value, 0, None)
                .await
                .expect("Request random value should be sent");
            // event MessageQueued
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            let request_id = result.return_value().expect("Request id not found");

            // then a response is received
            let random_value = Some(51_u128);
            let payload = RandomValueResponseMessage {
                resp_type: TYPE_RESPONSE,
                request: RandomValueRequestMessage {
                    requestor_id: ink::primitives::AccountId::from(
                        ink_e2e::charlie().public_key().0,
                    ),
                    requestor_nonce: 1,
                    min: 51_u128, // bad rpc that update the min and max values
                    max: 51_u128,
                },
                js_script_hash: Some([1u8; 32]),
                random_value,
                error: None,
            };
            let actions = vec![
                HandleActionInput::Reply(payload.encode()),
                HandleActionInput::SetQueueHead(request_id + 1),
            ];
            let rollup_cond_eq = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            assert!(
                result.is_err(),
                "We should not accept response with bad initial request"
            );

            Ok(())
        }

        #[ink_e2e::test]
        async fn test_receive_error(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // given
            let contract_id = alice_instantiates_contract(&mut client).await;

            // set the js code hash
            alice_set_js_script_hash(&mut client, &contract_id).await;

            // bob is granted as attestor
            alice_grants_bob_as_attestor(&mut client, &contract_id).await;

            // a random value is requested
            let request_random_value = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.request_random_value(100_u128, 1000_u128));
            let result = client
                .call(&ink_e2e::charlie(), request_random_value, 0, None)
                .await
                .expect("Request price should be sent");
            // event MessageQueued
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            let request_id = result.return_value().expect("Request id not found");

            // then a response is received
            let payload = RandomValueResponseMessage {
                resp_type: TYPE_ERROR,
                request: RandomValueRequestMessage {
                    requestor_id: ink::primitives::AccountId::from(
                        ink_e2e::charlie().public_key().0,
                    ),
                    requestor_nonce: 1,
                    min: 100_u128,
                    max: 1000_u128,
                },
                js_script_hash: Some([1u8; 32]),
                error: Some(12356.encode()),
                random_value: None,
            };
            let actions = vec![
                HandleActionInput::Reply(payload.encode()),
                HandleActionInput::SetQueueHead(request_id + 1),
            ];
            let rollup_cond_eq = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client
                .call(&ink_e2e::bob(), rollup_cond_eq, 0, None)
                .await
                .expect("we should proceed error message");
            // two events : MessageProcessedTo and PricesReceived
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            Ok(())
        }

        #[ink_e2e::test]
        async fn test_bad_attestor(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // given
            let contract_id = alice_instantiates_contract(&mut client).await;

            // set the js code hash
            alice_set_js_script_hash(&mut client, &contract_id).await;

            // bob is not granted as attestor => it should not be able to send a message
            let rollup_cond_eq = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], vec![]));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            assert!(
                result.is_err(),
                "only attestor should be able to send messages"
            );

            // bob is granted as attestor
            alice_grants_bob_as_attestor(&mut client, &contract_id).await;

            // then bob is able to send a message
            let rollup_cond_eq = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], vec![]));
            let result = client
                .call(&ink_e2e::bob(), rollup_cond_eq, 0, None)
                .await
                .expect("rollup cond eq failed");
            // no event
            assert!(!result.contains_event("Contracts", "ContractEmitted"));

            Ok(())
        }


        #[ink_e2e::test]
        async fn test_bad_js_code_hash(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // given
            let contract_id = alice_instantiates_contract(&mut client).await;

            // set the js code hash
            alice_set_js_script_hash(&mut client, &contract_id).await;

            // bob is granted as attestor
            alice_grants_bob_as_attestor(&mut client, &contract_id).await;

            // a request is sent
            let request_random_value = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.request_random_value(0_u128, 1000000000_u128));
            let result = client
                .call(&ink_e2e::charlie(), request_random_value, 0, None)
                .await
                .expect("Request random value should be sent");
            // event MessageQueued
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            let request_id = result.return_value().expect("Request id not found");

            // then a response is received
            let random_value = Some(51_u128);
            let payload = RandomValueResponseMessage {
                resp_type: TYPE_RESPONSE,
                request: RandomValueRequestMessage {
                    requestor_id: ink::primitives::AccountId::from(
                        ink_e2e::charlie().public_key().0,
                    ),
                    requestor_nonce: 1,
                    min: 0_u128, // bad rpc that update the min and max values
                    max: 1000000000_u128,
                },
                js_script_hash: Some([2u8; 32]), // bad js code hash
                random_value,
                error: None,
            };
            let actions = vec![
                HandleActionInput::Reply(payload.encode()),
                HandleActionInput::SetQueueHead(request_id + 1),
            ];
            let rollup_cond_eq = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            assert!(
                result.is_err(),
                "We should not accept response with bad js code hash"
            );

            Ok(())
        }


        #[ink_e2e::test]
        async fn test_bad_messages(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // given

            let contract_id = alice_instantiates_contract(&mut client).await;

            // set the js code hash
            alice_set_js_script_hash(&mut client, &contract_id).await;

            // bob is granted as attestor
            alice_grants_bob_as_attestor(&mut client, &contract_id).await;

            let actions = vec![HandleActionInput::Reply(58u128.encode())];
            let rollup_cond_eq = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            assert!(
                result.is_err(),
                "we should not be able to proceed bad messages"
            );

            Ok(())
        }

        #[ink_e2e::test]
        async fn test_optimistic_locking(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // given

            let contract_id = alice_instantiates_contract(&mut client).await;

            // set the js code hash
            alice_set_js_script_hash(&mut client, &contract_id).await;

            // bob is granted as attestor
            alice_grants_bob_as_attestor(&mut client, &contract_id).await;

            // then bob sends a message
            // from v0 to v1 => it's ok
            let conditions = vec![(123u8.encode(), None)];
            let updates = vec![(123u8.encode(), Some(1u128.encode()))];
            let rollup_cond_eq = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(conditions.clone(), updates.clone(), vec![]));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            result.expect("This message should be proceed because the condition is met");

            // test idempotency it should fail because the conditions are not met
            let rollup_cond_eq = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(conditions.clone(), updates.clone(), vec![]));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            assert!(
                result.is_err(),
                "This message should not be proceed because the condition is not met"
            );

            // from v1 to v2 => it's ok
            let conditions = vec![(123u8.encode(), Some(1u128.encode()))];
            let updates = vec![(123u8.encode(), Some(2u128.encode()))];
            let rollup_cond_eq = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(conditions.clone(), updates.clone(), vec![]));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            result.expect("This message should be proceed because the condition is met");

            // test idempotency it should fail because the conditions are not met
            let rollup_cond_eq = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(conditions.clone(), updates.clone(), vec![]));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            assert!(
                result.is_err(),
                "This message should not be proceed because the condition is not met"
            );

            Ok(())
        }

        ///
        /// Test the meta transactions
        /// Alice is the owner
        /// Bob is the attestor
        /// Charlie is the sender (ie the payer)
        ///
        #[ink_e2e::test]
        async fn test_meta_tx_rollup_cond_eq(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            let contract_id = alice_instantiates_contract(&mut client).await;

            // Bob is the attestor
            // use the ecsda account because we are not able to verify the sr25519 signature
            let from = ink::primitives::AccountId::from(
                Signer::<PolkadotConfig>::account_id(&subxt_signer::ecdsa::dev::bob()).0,
            );

            // add the role => it should be succeed
            let grant_role = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.grant_role(ATTESTOR_ROLE, Some(from)));
            client
                .call(&ink_e2e::alice(), grant_role, 0, None)
                .await
                .expect("grant the attestor failed");

            // prepare the meta transaction
            let data = RollupCondEqMethodParams::encode(&(vec![], vec![], vec![]));
            let prepare_meta_tx = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.prepare(from, data.clone()));
            let result = client
                .call(&ink_e2e::bob(), prepare_meta_tx, 0, None)
                .await
                .expect("We should be able to prepare the meta tx");

            let (request, _hash) = result
                .return_value()
                .expect("Expected value when preparing meta tx");

            assert_eq!(0, request.nonce);
            assert_eq!(from, request.from);
            assert_eq!(contract_id, request.to);
            assert_eq!(&data, &request.data);

            // Bob signs the message
            let keypair = subxt_signer::ecdsa::dev::bob();
            let signature = keypair.sign(&scale::Encode::encode(&request)).0;

            // do the meta tx: charlie sends the message
            let meta_tx_rollup_cond_eq = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.meta_tx_rollup_cond_eq(request.clone(), signature));
            client
                .call(&ink_e2e::charlie(), meta_tx_rollup_cond_eq, 0, None)
                .await
                .expect("meta tx rollup cond eq should not failed");

            // do it again => it must failed
            let meta_tx_rollup_cond_eq = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.meta_tx_rollup_cond_eq(request.clone(), signature));
            let result = client
                .call(&ink_e2e::charlie(), meta_tx_rollup_cond_eq, 0, None)
                .await;
            assert!(
                result.is_err(),
                "This message should not be proceed because the nonce is obsolete"
            );

            Ok(())
        }
    }
}
