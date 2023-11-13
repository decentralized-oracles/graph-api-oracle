#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[openbrush::implementation(Ownable, AccessControl, Upgradeable)]
#[openbrush::contract]
pub mod graph_api_consumer {
    use ink::codegen::{EmitEvent, Env};
    use ink::prelude::string::{String, ToString};
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

    pub type DappId = String;

    /// Events emitted when a value is requested
    #[ink(event)]
    pub struct ValueRequested {
        /// dApp id requested
        dapp_id: DappId,
        /// when the value has been requested
        timestamp: u64,
    }

    /// Events emitted when a value is received
    #[ink(event)]
    pub struct ValueReceived {
        /// dApp id requested
        dapp_id: DappId,
        /// stats
        stats: DappStats,
        /// when the value has been received
        timestamp: u64,
    }

    /// Events emitted when an error is received
    #[ink(event)]
    pub struct ErrorReceived {
        /// dApp id requested
        dapp_id: DappId,
        /// error
        error: Vec<u8>,
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

    /// Message to request the data
    /// message pushed in the queue by the Ink! smart contract and read by the offchain rollup
    #[derive(Eq, PartialEq, Clone, scale::Encode, scale::Decode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct GraphApiRequestMessage {
        /// id of the dapp
        dapp_id: DappId,
    }

    #[derive(Encode, Decode, Default, Eq, PartialEq, Clone, Debug)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct DappStats {
        developer_address: String,
        nb_stakers: u64,
        total_stake: Balance,
    }

    /// Message sent to provide the data
    /// response pushed in the queue by the offchain rollup and read by the Ink! smart contract
    #[derive(Encode, Decode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct GraphApiResponseMessage {
        /// id of the dapp
        dapp_id: DappId,
        /// stats
        stats: DappStats,
    }

    /// Message sent to provide the data
    /// response pushed in the queue by the offchain rollup and read by the Ink! smart contract
    #[derive(Encode, Decode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    enum ResponseMessage {
        JsResponse {
            /// hash of js script executed to get the data
            js_script_hash: CodeHash,
            /// hash of data in input of js
            input_hash: CodeHash,
            /// hash of settings of js
            settings_hash: CodeHash,
            /// response value
            output_value: Vec<u8>,
        },
        Error {
            /// hash of js script
            js_script_hash: CodeHash,
            /// input in js
            input_value: Vec<u8>,
            /// hash of settings of js
            settings_hash: CodeHash,
            /// when an error occurs
            error: Vec<u8>,
        },
    }

    /// Data storage
    #[derive(Encode, Decode, Default, Eq, PartialEq, Clone, Debug)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct DappData {
        /// id of the dApp
        dapp_id: DappId,
        /// stats of the dApp
        dapp_stats: DappStats,
        /// when the last value has been updated
        last_update: u64,
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
        /// hash of js script executed to query the data
        js_script_hash: Lazy<CodeHash>,
        /// hash of settings given in parameter to js runner
        settings_hash: Lazy<CodeHash>,
        /// data linked to the dApps
        dapps_data: Mapping<DappId, DappData>,
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
        pub fn get_dapp_data(&self, dapp_id: DappId) -> Option<DappData> {
            self.dapps_data.get(dapp_id)
        }

        #[ink(message)]
        pub fn get_request_message_raw(
            &self,
            dapp_id: DappId,
        ) -> Vec<u8> {
            let message = GraphApiRequestMessage {
                dapp_id,
            };
            message.encode()
        }

        #[ink(message)]
        pub fn request_dapp_data(
            &mut self,
            dapp_id: DappId,
        ) -> Result<QueueIndex, ContractError> {
            // push the message in the queue
            let message = GraphApiRequestMessage {
                dapp_id: dapp_id.to_string(),
            };

            let message_id = self.push_message(&message)?;

            // emmit te event
            self.env().emit_event(ValueRequested {
                dapp_id,
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
        pub fn set_js_script_hash(
            &mut self,
            js_script_hash: CodeHash,
        ) -> Result<(), ContractError> {
            self.js_script_hash.set(&js_script_hash);
            Ok(())
        }

        #[ink(message)]
        pub fn get_js_script_hash(&self) -> Option<CodeHash> {
            self.js_script_hash.get()
        }


        #[ink(message)]
        #[openbrush::modifiers(access_control::only_role(MANAGER_ROLE))]
        pub fn set_settings_hash(
            &mut self,
            settings_hash: CodeHash,
        ) -> Result<(), ContractError> {
            self.settings_hash.set(&settings_hash);
            Ok(())
        }

        #[ink(message)]
        pub fn get_settings_hash(&self) -> Option<CodeHash> {
            self.settings_hash.get()
        }

    }

    impl RollupAnchor for GraphApiOracleClient {}
    impl MetaTransaction for GraphApiOracleClient {}

    impl rollup_anchor::MessageHandler for GraphApiOracleClient {
        fn on_message_received(&mut self, action: Vec<u8>) -> Result<(), RollupAnchorError> {
            // parse the response
            let response: ResponseMessage =
                Decode::decode(&mut &action[..]).or(Err(RollupAnchorError::FailedToDecode))?;

            let timestamp = self.env().block_timestamp();

            match response {
                ResponseMessage::JsResponse {
                    js_script_hash,
                    settings_hash,
                    output_value ,
                    ..
                } => {
                    // check the js code hash
                    match self.js_script_hash.get() {
                        Some(expected_js_hash) => {
                            if js_script_hash != expected_js_hash {
                                return Err(RollupAnchorError::ConditionNotMet); // improve the error
                            }
                        },
                        None => {}
                    }

                    // check the settings hash
                    match self.settings_hash.get() {
                        Some(expected_settings_hash) => {
                            if settings_hash != expected_settings_hash {
                                return Err(RollupAnchorError::ConditionNotMet); // improve the error
                            }
                        },
                        None => {}
                    }

                    // we received the data
                    let message = GraphApiResponseMessage::decode(&mut output_value.as_slice())
                        .map_err(|_| RollupAnchorError::FailedToDecode)?;

                    let dapp_id = message.dapp_id;
                    let dapp_stats = message.stats;

                    let dapp_data = DappData {
                        dapp_id: dapp_id.to_string(),
                        dapp_stats: DappStats {
                            total_stake: dapp_stats.total_stake,
                            nb_stakers: dapp_stats.nb_stakers,
                            developer_address: dapp_stats.developer_address.to_string(),
                        },
                        last_update: timestamp,
                    };

                    // register the info
                    self.dapps_data.insert(dapp_id.to_string(), &dapp_data);

                    // emmit the event
                    self.env().emit_event(ValueReceived {
                        dapp_id,
                        stats: DappStats {
                            total_stake: dapp_stats.total_stake,
                            nb_stakers: dapp_stats.nb_stakers,
                            developer_address: dapp_stats.developer_address,
                        },
                        timestamp,
                    });
                }
                ResponseMessage::Error { error, input_value, .. } => {
                    // we received an error

                    let input = GraphApiRequestMessage::decode(&mut input_value.as_slice())
                        .map_err(|_| RollupAnchorError::FailedToDecode)?;

                    self.env().emit_event(ErrorReceived {
                        dapp_id : input.dapp_id,
                        error: error,
                        timestamp,
                    });
                }
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
        use crate::graph_api_consumer::ResponseMessage::{Error, JsResponse};

        type E2EResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

        async fn alice_instantiates_contract(
            client: &mut ink_e2e::Client<PolkadotConfig, DefaultEnvironment>,
        ) -> AccountId {
            let constructor = GraphApiOracleClientRef::new();
            client
                .instantiate(
                    "graph_api_consumer",
                    &ink_e2e::alice(),
                    constructor,
                    0,
                    None,
                )
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

        async fn alice_set_settings_hash(
            client: &mut ink_e2e::Client<PolkadotConfig, DefaultEnvironment>,
            contract_id: &AccountId,
        ) {
            let code_hash = [2u8; 32];
            let set_settings_hash = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.set_settings_hash(code_hash));
            client
                .call(&ink_e2e::alice(), set_settings_hash, 0, None)
                .await
                .expect("set settings hash failed");
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
        async fn test_receive_feed(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // given
            let contract_id = alice_instantiates_contract(&mut client).await;

            // set the js code hash
            alice_set_js_script_hash(&mut client, &contract_id).await;

            // set the settings code hash
            alice_set_settings_hash(&mut client, &contract_id).await;

            // bob is granted as attestor
            alice_grants_bob_as_attestor(&mut client, &contract_id).await;

            let dapp_id = "zsv1gvepvmwfdshmwgczs4zyvmmwesbjwqjn4wdpuefrrpy".to_string();
            let developer_address = "zsv1gvepvmwfdshmwgczs4zyvmmwesbjwqjn4wdpuefrrpy".to_string();
            let nb_stakers = 82;
            let total_stake = 999999999999999999999999999999999;

            // data is received
            let response = GraphApiResponseMessage {
                dapp_id: dapp_id.to_string(),
                stats : DappStats {
                    developer_address: developer_address.to_string(),
                    nb_stakers,
                    total_stake,
                },
            };
            let payload = JsResponse {
                js_script_hash: [1u8; 32],
                input_hash: [3u8; 32],
                settings_hash: [2u8; 32],
                output_value: response.encode(),
            };
            let actions = vec![HandleActionInput::Reply(payload.encode())];
            let rollup_cond_eq = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client
                .call(&ink_e2e::bob(), rollup_cond_eq, 0, None)
                .await
                .expect("rollup cond eq should be ok");
            // two events : MessageProcessedTo and ValueReceived
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            // and check if the data is filled
            let get_dapp_data = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.get_dapp_data(dapp_id.to_string()));
            let get_res = client
                .call_dry_run(&ink_e2e::charlie(), &get_dapp_data, 0, None)
                .await;
            let dapp_data = get_res.return_value().expect("Dapp data not found");

            assert_eq!(dapp_id, dapp_data.dapp_id);
            assert_eq!(developer_address, dapp_data.dapp_stats.developer_address);
            assert_eq!(nb_stakers, dapp_data.dapp_stats.nb_stakers);
            assert_eq!(total_stake, dapp_data.dapp_stats.total_stake);
            assert_ne!(0, dapp_data.last_update);

            Ok(())
        }

        #[ink_e2e::test]
        async fn test_receive_error(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // given
            let contract_id = alice_instantiates_contract(&mut client).await;

            // set the js code hash
            alice_set_js_script_hash(&mut client, &contract_id).await;

            // set the settings code hash
            alice_set_settings_hash(&mut client, &contract_id).await;

            // bob is granted as attestor
            alice_grants_bob_as_attestor(&mut client, &contract_id).await;

            let dapp_id = "zsv1gvepvmwfdshmwgczs4zyvmmwesbjwqjn4wdpuefrrpy".to_string();
            let input_data = GraphApiRequestMessage {
                dapp_id: dapp_id.to_string(),
            };

            // then a response is received
            let error = vec![3u8; 5];
            let payload = Error {
                js_script_hash: [1u8; 32],
                input_value: input_data.encode(),
                settings_hash: [2u8; 32],
                error,
            };
            let actions = vec![HandleActionInput::Reply(payload.encode())];
            let rollup_cond_eq = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client
                .call(&ink_e2e::bob(), rollup_cond_eq, 0, None)
                .await
                .expect("we should proceed error message");
            // two events : MessageProcessedTo and ErrorReceived
            assert!(result.contains_event("Contracts", "ContractEmitted"));

            Ok(())
        }

        #[ink_e2e::test]
        async fn test_bad_attestor(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // given
            let contract_id = alice_instantiates_contract(&mut client).await;

            // set the js code hash
            alice_set_js_script_hash(&mut client, &contract_id).await;

            // set the settings code hash
            alice_set_settings_hash(&mut client, &contract_id).await;

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
        async fn test_bad_hash(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // given
            let contract_id = alice_instantiates_contract(&mut client).await;

            // set the js code hash
            alice_set_js_script_hash(&mut client, &contract_id).await;

            // set the settings code hash
            alice_set_settings_hash(&mut client, &contract_id).await;

            // bob is granted as attestor
            alice_grants_bob_as_attestor(&mut client, &contract_id).await;

            // a response is received
            let dapp_id = "zsv1gvepvmwfdshmwgczs4zyvmmwesbjwqjn4wdpuefrrpy".to_string();
            let developer_address = "zsv1gvepvmwfdshmwgczs4zyvmmwesbjwqjn4wdpuefrrpy".to_string();
            let nb_stakers = 82;
            let total_stake = 999999999999999999999999999999999;

            // data is received
            let response = GraphApiResponseMessage {
                dapp_id,
                stats : DappStats {
                    developer_address,
                    nb_stakers,
                    total_stake,
                },
            };
            let payload = JsResponse {
                js_script_hash: [9u8; 32],
                input_hash: [3u8; 32],
                settings_hash: [2u8; 32],
                output_value: response.encode(),
            };
            let actions = vec![HandleActionInput::Reply(payload.encode())];
            let rollup_cond_eq = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            assert!(
                result.is_err(),
                "We should not accept response with bad js code hash"
            );

            let payload = JsResponse {
                js_script_hash: [1u8; 32],
                input_hash: [3u8; 32],
                settings_hash: [9u8; 32],
                output_value: response.encode(),
            };
            let actions = vec![HandleActionInput::Reply(payload.encode())];
            let rollup_cond_eq = build_message::<GraphApiOracleClientRef>(contract_id.clone())
                .call(|oracle| oracle.rollup_cond_eq(vec![], vec![], actions.clone()));
            let result = client.call(&ink_e2e::bob(), rollup_cond_eq, 0, None).await;
            assert!(
                result.is_err(),
                "We should not accept response with bad settings code hash"
            );

            Ok(())
        }

        #[ink_e2e::test]
        async fn test_bad_messages(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            // given

            let contract_id = alice_instantiates_contract(&mut client).await;

            // set the js code hash
            alice_set_js_script_hash(&mut client, &contract_id).await;

            // set the settings code hash
            alice_set_settings_hash(&mut client, &contract_id).await;

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
            let meta_tx_rollup_cond_eq =
                build_message::<GraphApiOracleClientRef>(contract_id.clone())
                    .call(|oracle| oracle.meta_tx_rollup_cond_eq(request.clone(), signature));
            client
                .call(&ink_e2e::charlie(), meta_tx_rollup_cond_eq, 0, None)
                .await
                .expect("meta tx rollup cond eq should not failed");

            // do it again => it must failed
            let meta_tx_rollup_cond_eq =
                build_message::<GraphApiOracleClientRef>(contract_id.clone())
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
