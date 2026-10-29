module hoglet_wrap_v1_to_da::nft_wrapper {
    use std::bcs;
    use std::hash;
    use std::option::{Self, Option};
    use std::signer;
    use std::string::{Self, String};
    use std::vector;
    use supra_framework::account;
    use supra_framework::event;
    use supra_framework::object::{Self, Object};
    use aptos_std::error;
    use aptos_std::smart_table::{Self, SmartTable};
    use aptos_token_objects::collection;
    use aptos_token_objects::property_map;
    use aptos_token_objects::royalty::{Self, Royalty};
    use aptos_token_objects::token::{Self, Token, BurnRef};
    use aptos_token::property_map as property_map_v1;
    use aptos_token::token as tokenv1;

    // ================= Error Codes =================
    const E_NOT_OWNER: u64 = 2;
    const E_AMOUNT_MUST_BE_ONE: u64 = 4;
    const E_TOKEN_NOT_WRAPPED: u64 = 5;
    const E_COLLECTION_NOT_WRAPPED: u64 = 6;
    const E_VECTOR_LENGTH_MISMATCH: u64 = 7;
    const E_EMPTY_BATCH: u64 = 8;

    // ================= V2 Limits =================
    const MAX_V2_COLLECTION_NAME_LEN: u64 = 128;
    const MAX_V2_TOKEN_NAME_LEN: u64 = 128;
    const MAX_V2_URI_LEN: u64 = 512;
    const MAX_V2_DESCRIPTION_LEN: u64 = 2048;
    const MAX_V2_PROPERTY_KEY_LEN: u64 = 128;
    const MAX_MIGRATED_PROPERTIES: u64 = 100;

    // ================= Core Storage (Layout preserved for 100% compatible upgrade) =================
    struct WrapperConfig has key {
        treasury_cap: account::SignerCapability,
        // Maps the V2 Object Address -> V1 TokenId
        wrapped_tokens: SmartTable<address, tokenv1::TokenId>,
        // Keeps track of initiated collections to prevent double creation
        initiated_collections: SmartTable<String, bool>,
        // Stores BurnRef per wrapped token to guarantee burn capability
        burn_refs: SmartTable<address, BurnRef>,
    }

    /// Stored on each newly created V2 Collection Object for reverse V1 lookup and permissionless metadata sync
    struct WrappedCollectionMeta has key {
        v1_creator: address,
        v1_collection_name: String,
        mutator_ref: collection::MutatorRef,
    }

    /// Stored on each newly minted V2 Token Object to cleanly destroy its PropertyMap before burning
    struct WrappedTokenProps has key {
        prop_mutator_ref: property_map::MutatorRef,
    }

    // ================= Events =================
    #[event]
    struct CollectionWrappedEvent has drop, store {
        v1_creator: address,
        v1_collection: String,
        v2_collection_addr: address,
        v2_collection_name: String,
    }

    #[event]
    struct CollectionSyncedEvent has drop, store {
        v1_creator: address,
        v1_collection: String,
        v2_collection_addr: address,
        new_description: String,
        new_uri: String,
    }

    #[event]
    struct WrapEvent has drop, store {
        user: address,
        v2_token_addr: address,
        v1_creator: address,
        v1_collection: String,
        v1_token_name: String,
        v1_property_version: u64,
    }

    #[event]
    struct UnwrapEvent has drop, store {
        user: address,
        v2_token_addr: address,
        v1_creator: address,
        v1_collection: String,
        v1_token_name: String,
        v1_property_version: u64,
    }

    // ================= Initialization =================
    fun init_module(account: &signer) {
        let (_resource_signer, resource_cap) = account::create_resource_account(
            account,
            bcs::to_bytes(&string::utf8(b"NFT_WRAPPER_VAULT_V2"))
        );
        move_to(account, WrapperConfig {
            treasury_cap: resource_cap,
            wrapped_tokens: smart_table::new(),
            initiated_collections: smart_table::new(),
            burn_refs: smart_table::new(),
        });
    }

    #[test_only]
    public fun init_for_test(account: &signer) {
        init_module(account);
    }

    // ================= Internal Helpers =================
    fun bytes_to_hex_string(bytes: &vector<u8>): String {
        let hex_bytes = vector::empty<u8>();
        let hex_chars = b"0123456789abcdef";
        let i = 0;
        let len = vector::length(bytes);
        while (i < len) {
            let byte = *vector::borrow(bytes, i);
            vector::push_back(&mut hex_bytes, *vector::borrow(&hex_chars, ((byte >> 4) as u64)));
            vector::push_back(&mut hex_bytes, *vector::borrow(&hex_chars, ((byte & 0x0F) as u64)));
            i = i + 1;
        };
        string::utf8(hex_bytes)
    }

    /// Generates a deterministic V2 collection name <= 128 bytes.
    /// Preserves `"w_" + hex(creator) + "_" + collection` for collections <= 61 bytes,
    /// and falls back to `"w_h_" + hex(sha3_256(bcs(creator) || bcs(collection)))` (68 bytes)
    /// for long or multi-byte UTF-8 collection names so no V1 collection is ever DoS'd.
    fun get_wrapped_collection_name(creator: address, collection: &String): String {
        let creator_bytes = bcs::to_bytes(&creator);
        let candidate = string::utf8(b"w_");
        string::append(&mut candidate, bytes_to_hex_string(&creator_bytes));
        string::append(&mut candidate, string::utf8(b"_"));
        string::append(&mut candidate, *collection);

        if (string::length(&candidate) <= MAX_V2_COLLECTION_NAME_LEN) {
            candidate
        } else {
            let payload = creator_bytes;
            vector::append(&mut payload, bcs::to_bytes(collection));
            let digest = hash::sha3_256(payload);
            let hashed_name = string::utf8(b"w_h_");
            string::append(&mut hashed_name, bytes_to_hex_string(&digest));
            hashed_name
        }
    }

    fun sanitize_description(desc: String): String {
        if (string::length(&desc) <= MAX_V2_DESCRIPTION_LEN) {
            desc
        } else {
            string::utf8(b"Wrapped V1 Digital Asset")
        }
    }

    fun sanitize_uri(uri: String): String {
        if (string::length(&uri) <= MAX_V2_URI_LEN) {
            uri
        } else {
            string::utf8(b"")
        }
    }

    fun sanitize_token_name(name: String): String {
        if (string::length(&name) <= MAX_V2_TOKEN_NAME_LEN) {
            name
        } else {
            let digest = hash::sha3_256(bcs::to_bytes(&name));
            let fallback = string::utf8(b"t_h_");
            string::append(&mut fallback, bytes_to_hex_string(&digest));
            fallback
        }
    }

    /// Safely converts V1 royalty to V2 Royalty without aborting on 0/0 or malformed V1 values
    fun extract_v2_royalty(token_id: &tokenv1::TokenId): Option<Royalty> {
        let v1_royalty = tokenv1::get_royalty(*token_id);
        let num = tokenv1::get_royalty_numerator(&v1_royalty);
        let denom = tokenv1::get_royalty_denominator(&v1_royalty);
        let payee = tokenv1::get_royalty_payee(&v1_royalty);
        if (denom > 0 && num > 0 && num <= denom) {
            option::some(royalty::create(num, denom, payee))
        } else {
            option::none<Royalty>()
        }
    }

    fun slice_bytes(bytes: &vector<u8>, start: u64, end: u64): vector<u8> {
        let out = vector::empty<u8>();
        let i = start;
        while (i < end) {
            vector::push_back(&mut out, *vector::borrow(bytes, i));
            i = i + 1;
        };
        out
    }

    /// Safely decodes a ULEB128-prefixed BCS UTF-8 string (up to 16,383 bytes) without aborting
    fun try_decode_bcs_string(raw_bytes: &vector<u8>): Option<String> {
        let val_len = vector::length(raw_bytes);
        if (val_len == 0) {
            return option::none<String>()
        };
        let b0 = (*vector::borrow(raw_bytes, 0) as u64);
        if (b0 < 128) {
            if (b0 == val_len - 1) {
                let inner = slice_bytes(raw_bytes, 1, val_len);
                return string::try_utf8(inner)
            };
        } else if (val_len >= 2) {
            let b1 = (*vector::borrow(raw_bytes, 1) as u64);
            if (b1 < 128) {
                let str_len = (b0 & 0x7F) | (b1 << 7);
                if (str_len == val_len - 2) {
                    let inner = slice_bytes(raw_bytes, 2, val_len);
                    return string::try_utf8(inner)
                };
            };
        };
        option::none<String>()
    }

    /// Helper to cleanly add string properties with BCS decoding and UTF-8 fallback
    fun add_string_property(
        prop_mutator_ref: &property_map::MutatorRef,
        key: String,
        raw_bytes: vector<u8>,
        try_bcs: bool,
    ) {
        if (try_bcs) {
            let opt_bcs = try_decode_bcs_string(&raw_bytes);
            if (option::is_some(&opt_bcs)) {
                property_map::add_typed(prop_mutator_ref, key, option::destroy_some(opt_bcs));
                return
            };
        };
        let opt_raw = string::try_utf8(copy raw_bytes);
        if (option::is_some(&opt_raw)) {
            property_map::add_typed(prop_mutator_ref, key, option::destroy_some(opt_raw));
        } else {
            property_map::add_typed(prop_mutator_ref, key, raw_bytes);
        };
    }

    /// Migrates V1 PropertyMap attributes + canonical V1 identifiers onto the V2 Token Object,
    /// sanitizing non-standard V1 type descriptors so `aptos_token_objects::property_map` never aborts.
    fun init_v2_properties(
        constructor_ref: &object::ConstructorRef,
        vault_addr: address,
        token_id: &tokenv1::TokenId,
    ): property_map::MutatorRef {
        let empty_props = property_map::prepare_input(
            vector::empty<String>(),
            vector::empty<String>(),
            vector::empty<vector<u8>>(),
        );
        property_map::init(constructor_ref, empty_props);
        let prop_mutator_ref = property_map::generate_mutator_ref(constructor_ref);

        let (creator_address, _collection_name, _token_name, property_version) =
            tokenv1::get_token_id_fields(token_id);

        let key_v1_creator = string::utf8(b"__v1_creator");
        let key_v1_prop_ver = string::utf8(b"__v1_property_version");
        property_map::add_typed(&prop_mutator_ref, copy key_v1_creator, creator_address);
        property_map::add_typed(&prop_mutator_ref, copy key_v1_prop_ver, property_version);

        let v1_props = tokenv1::get_property_map(vault_addr, *token_id);
        let keys = property_map_v1::keys(&v1_props);
        let total_keys = vector::length(&keys);
        let limit = if (total_keys > MAX_MIGRATED_PROPERTIES) {
            MAX_MIGRATED_PROPERTIES
        } else {
            total_keys
        };

        let t_bool = string::utf8(b"bool");
        let t_u8 = string::utf8(b"u8");
        let t_u16 = string::utf8(b"u16");
        let t_u32 = string::utf8(b"u32");
        let t_u64 = string::utf8(b"u64");
        let t_u128 = string::utf8(b"u128");
        let t_u256 = string::utf8(b"u256");
        let t_addr = string::utf8(b"address");
        let t_str_canonical = string::utf8(b"0x1::string::String");
        let t_str_lower = string::utf8(b"string");
        let t_str_pascal = string::utf8(b"String");

        let i = 0;
        while (i < limit) {
            let key = *vector::borrow(&keys, i);
            let key_len = string::length(&key);
            if (key_len > 0
                && key_len <= MAX_V2_PROPERTY_KEY_LEN
                && &key != &key_v1_creator
                && &key != &key_v1_prop_ver) {
                let prop_val = property_map_v1::borrow(&v1_props, &key);
                let raw_type = property_map_v1::borrow_type(prop_val);
                let raw_bytes = property_map_v1::borrow_value(prop_val);
                let val_len = vector::length(&raw_bytes);

                if (&raw_type == &t_bool && val_len == 1 && *vector::borrow(&raw_bytes, 0) <= 1) {
                    property_map::add(&prop_mutator_ref, key, copy t_bool, raw_bytes);
                } else if (&raw_type == &t_u8 && val_len == 1) {
                    property_map::add(&prop_mutator_ref, key, copy t_u8, raw_bytes);
                } else if (&raw_type == &t_u16 && val_len == 2) {
                    property_map::add(&prop_mutator_ref, key, copy t_u16, raw_bytes);
                } else if (&raw_type == &t_u32 && val_len == 4) {
                    property_map::add(&prop_mutator_ref, key, copy t_u32, raw_bytes);
                } else if (&raw_type == &t_u64 && val_len == 8) {
                    property_map::add(&prop_mutator_ref, key, copy t_u64, raw_bytes);
                } else if (&raw_type == &t_u128 && val_len == 16) {
                    property_map::add(&prop_mutator_ref, key, copy t_u128, raw_bytes);
                } else if (&raw_type == &t_u256 && val_len == 32) {
                    property_map::add(&prop_mutator_ref, key, copy t_u256, raw_bytes);
                } else if (&raw_type == &t_addr && val_len == 32) {
                    property_map::add(&prop_mutator_ref, key, copy t_addr, raw_bytes);
                } else if (&raw_type == &t_str_canonical) {
                    add_string_property(&prop_mutator_ref, key, raw_bytes, true);
                } else if (&raw_type == &t_str_lower || &raw_type == &t_str_pascal) {
                    let try_bcs = val_len > 0 && *vector::borrow(&raw_bytes, 0) < 32;
                    add_string_property(&prop_mutator_ref, key, raw_bytes, try_bcs);
                } else {
                    property_map::add_typed(&prop_mutator_ref, key, raw_bytes);
                };
            };
            i = i + 1;
        };

        prop_mutator_ref
    }

    /// Internal function to ensure the V2 collection exists automatically
    fun init_collection_if_needed(
        config: &mut WrapperConfig,
        vault_signer: &signer,
        creator_address: address,
        collection_name: &String,
        wrapped_col_name: &String,
    ) {
        if (smart_table::contains(&config.initiated_collections, *wrapped_col_name)) {
            return
        };

        let raw_desc = tokenv1::get_collection_description(creator_address, *collection_name);
        let raw_uri = tokenv1::get_collection_uri(creator_address, *collection_name);

        let collection_ref = collection::create_unlimited_collection(
            vault_signer,
            sanitize_description(raw_desc),
            *wrapped_col_name,
            option::none<Royalty>(),
            sanitize_uri(raw_uri),
        );

        let col_signer = object::generate_signer(&collection_ref);
        let mutator_ref = collection::generate_mutator_ref(&collection_ref);
        move_to(&col_signer, WrappedCollectionMeta {
            v1_creator: creator_address,
            v1_collection_name: *collection_name,
            mutator_ref,
        });

        smart_table::add(&mut config.initiated_collections, *wrapped_col_name, true);

        event::emit(CollectionWrappedEvent {
            v1_creator: creator_address,
            v1_collection: *collection_name,
            v2_collection_addr: object::address_from_constructor_ref(&collection_ref),
            v2_collection_name: *wrapped_col_name,
        });
    }

    // ================= Entry Functions (Direct Wallet / dApp Access) =================

    /// Allows an end-user to wrap a V1 NFT directly from a wallet or frontend transaction
    public entry fun wrap_entry(
        user: &signer,
        creator: address,
        collection: String,
        name: String,
        property_version: u64,
    ) acquires WrapperConfig {
        let token_id = tokenv1::create_token_id_raw(creator, collection, name, property_version);
        let v1_token = tokenv1::withdraw_token(user, token_id, 1);
        let _v2_obj = wrap_v1_to_da(user, v1_token);
    }

    /// Allows an end-user to wrap multiple V1 NFTs in a single atomic transaction
    public entry fun wrap_batch_entry(
        user: &signer,
        creators: vector<address>,
        collections: vector<String>,
        names: vector<String>,
        property_versions: vector<u64>,
    ) acquires WrapperConfig {
        let len = vector::length(&creators);
        assert!(len > 0, error::invalid_argument(E_EMPTY_BATCH));
        assert!(
            len == vector::length(&collections)
                && len == vector::length(&names)
                && len == vector::length(&property_versions),
            error::invalid_argument(E_VECTOR_LENGTH_MISMATCH)
        );

        let i = 0;
        while (i < len) {
            let token_id = tokenv1::create_token_id_raw(
                *vector::borrow(&creators, i),
                *vector::borrow(&collections, i),
                *vector::borrow(&names, i),
                *vector::borrow(&property_versions, i),
            );
            let v1_token = tokenv1::withdraw_token(user, token_id, 1);
            let _v2_obj = wrap_v1_to_da(user, v1_token);
            i = i + 1;
        };
    }

    /// Guaranteed autonomous exit: allows any V2 NFT holder to unwrap back to V1 directly from their wallet
    public entry fun unwrap_entry(
        user: &signer,
        v2_token: Object<Token>,
    ) acquires WrapperConfig, WrappedTokenProps {
        let v1_token = unwrap_da_to_v1(user, v2_token);
        tokenv1::deposit_token(user, v1_token);
    }

    /// Allows an end-user to unwrap multiple V2 NFTs back to V1 in a single atomic transaction
    public entry fun unwrap_batch_entry(
        user: &signer,
        v2_tokens: vector<Object<Token>>,
    ) acquires WrapperConfig, WrappedTokenProps {
        let len = vector::length(&v2_tokens);
        assert!(len > 0, error::invalid_argument(E_EMPTY_BATCH));

        let i = 0;
        while (i < len) {
            let v2_token = *vector::borrow(&v2_tokens, i);
            let v1_token = unwrap_da_to_v1(user, v2_token);
            tokenv1::deposit_token(user, v1_token);
            i = i + 1;
        };
    }

    /// Permissionless (admin-free) sync of V2 collection URI and description from V1 on-chain state
    public entry fun sync_collection_metadata(
        creator: address,
        collection_name: String,
    ) acquires WrapperConfig, WrappedCollectionMeta {
        let col_addr = get_wrapped_collection_address(creator, copy collection_name);
        assert!(exists<WrappedCollectionMeta>(col_addr), error::not_found(E_COLLECTION_NOT_WRAPPED));

        let meta = borrow_global<WrappedCollectionMeta>(col_addr);
        let new_desc = sanitize_description(tokenv1::get_collection_description(creator, copy collection_name));
        let new_uri = sanitize_uri(tokenv1::get_collection_uri(creator, copy collection_name));
        collection::set_description(&meta.mutator_ref, copy new_desc);
        collection::set_uri(&meta.mutator_ref, copy new_uri);

        event::emit(CollectionSyncedEvent {
            v1_creator: creator,
            v1_collection: collection_name,
            v2_collection_addr: col_addr,
            new_description: new_desc,
            new_uri,
        });
    }

    // ================= Composable Public Functions (ABI-compatible with dao_router) =================

    /// Takes a V1 Token struct, locks it, and returns a V2 Object transferred to the user
    public fun wrap_v1_to_da(user: &signer, v1_token: tokenv1::Token): Object<Token> acquires WrapperConfig {
        // Validate: only slices with amount == 1 (prevent multi-edition truncation loss)
        assert!(tokenv1::get_token_amount(&v1_token) == 1, error::invalid_argument(E_AMOUNT_MUST_BE_ONE));

        let config = borrow_global_mut<WrapperConfig>(@hoglet_wrap_v1_to_da);
        let vault_signer = account::create_signer_with_capability(&config.treasury_cap);
        let vault_addr = signer::address_of(&vault_signer);

        let token_id = tokenv1::get_token_id(&v1_token);
        let token_data = tokenv1::get_tokendata_id(copy token_id);
        let (creator_address, collection_name, token_name, property_version) =
            tokenv1::get_token_id_fields(&token_id);
        let wrapped_col_name = get_wrapped_collection_name(creator_address, &collection_name);

        // Ensure V2 collection is created automatically
        init_collection_if_needed(config, &vault_signer, creator_address, &collection_name, &wrapped_col_name);

        let v2_royalty = extract_v2_royalty(&token_id);

        // LOCK: Deposit V1 token struct into vault's TokenStore
        tokenv1::deposit_token(&vault_signer, v1_token);

        let raw_desc = tokenv1::get_tokendata_description(copy token_data);
        let raw_uri = tokenv1::get_tokendata_uri(creator_address, token_data);

        // MINT: Create V2 token using DA standard directly
        let constructor_ref = token::create(
            &vault_signer,
            wrapped_col_name,
            sanitize_description(raw_desc),
            sanitize_token_name(copy token_name),
            v2_royalty,
            sanitize_uri(raw_uri),
        );

        let minted_token_addr = object::address_from_constructor_ref(&constructor_ref);

        // Migrate V1 PropertyMap attributes + canonical V1 identifiers onto the V2 Token Object
        let prop_mutator_ref = init_v2_properties(
            &constructor_ref,
            vault_addr,
            &token_id,
        );
        let token_signer = object::generate_signer(&constructor_ref);
        move_to(&token_signer, WrappedTokenProps { prop_mutator_ref });

        // Store BurnRef to guarantee we can always burn this token
        let burn_ref = token::generate_burn_ref(&constructor_ref);
        smart_table::add(&mut config.burn_refs, minted_token_addr, burn_ref);

        // SAVE STATE: Map V2 object to V1 TokenId
        smart_table::add(&mut config.wrapped_tokens, minted_token_addr, token_id);

        let minted_token = object::address_to_object<Token>(minted_token_addr);

        // Transfer ownership of the minted V2 object to the user
        let user_addr = signer::address_of(user);
        object::transfer(&vault_signer, copy minted_token, user_addr);

        event::emit(WrapEvent {
            user: user_addr,
            v2_token_addr: minted_token_addr,
            v1_creator: creator_address,
            v1_collection: collection_name,
            v1_token_name: token_name,
            v1_property_version: property_version,
        });

        minted_token
    }

    /// Takes a V2 Object, burns it, and returns the original V1 Token struct
    public fun unwrap_da_to_v1(
        user: &signer,
        v2_token: Object<Token>,
    ): tokenv1::Token acquires WrapperConfig, WrappedTokenProps {
        let user_addr = signer::address_of(user);
        assert!(object::owner(copy v2_token) == user_addr, error::permission_denied(E_NOT_OWNER));

        let v2_token_addr = object::object_address(&v2_token);
        let config = borrow_global_mut<WrapperConfig>(@hoglet_wrap_v1_to_da);
        assert!(
            smart_table::contains(&config.wrapped_tokens, v2_token_addr),
            error::not_found(E_TOKEN_NOT_WRAPPED)
        );

        // Extract V1 TokenId & BurnRef
        let token_id = smart_table::remove(&mut config.wrapped_tokens, v2_token_addr);
        let burn_ref = smart_table::remove(&mut config.burn_refs, v2_token_addr);

        // Clean up custom PropertyMap extension (if present) BEFORE burning the underlying V2 ObjectCore
        if (exists<WrappedTokenProps>(v2_token_addr)) {
            let WrappedTokenProps { prop_mutator_ref } = move_from<WrappedTokenProps>(v2_token_addr);
            property_map::burn(prop_mutator_ref);
        };

        // BURN V2 TOKEN using stored BurnRef
        token::burn(burn_ref);

        let (creator_address, collection_name, token_name, property_version) =
            tokenv1::get_token_id_fields(&token_id);

        // UNLOCK V1 TOKEN: Withdraw from vault and return as struct
        let vault_signer = account::create_signer_with_capability(&config.treasury_cap);
        let v1_token = tokenv1::withdraw_token(&vault_signer, token_id, 1);

        event::emit(UnwrapEvent {
            user: user_addr,
            v2_token_addr,
            v1_creator: creator_address,
            v1_collection: collection_name,
            v1_token_name: token_name,
            v1_property_version: property_version,
        });

        v1_token
    }

    // ================= View Functions =================

    #[view]
    public fun get_vault_address(): address acquires WrapperConfig {
        let config = borrow_global<WrapperConfig>(@hoglet_wrap_v1_to_da);
        account::get_signer_capability_address(&config.treasury_cap)
    }

    #[view]
    public fun get_wrapped_collection_address(creator: address, collection_name: String): address acquires WrapperConfig {
        let config = borrow_global<WrapperConfig>(@hoglet_wrap_v1_to_da);
        let vault_addr = account::get_signer_capability_address(&config.treasury_cap);
        let wrapped_col_name = get_wrapped_collection_name(creator, &collection_name);
        collection::create_collection_address(&vault_addr, &wrapped_col_name)
    }

    #[view]
    public fun is_wrapped(v2_token_addr: address): bool acquires WrapperConfig {
        let config = borrow_global<WrapperConfig>(@hoglet_wrap_v1_to_da);
        smart_table::contains(&config.wrapped_tokens, v2_token_addr)
    }

    #[view]
    public fun get_wrapped_token_info(v2_token_addr: address): (address, String, String, u64) acquires WrapperConfig {
        let config = borrow_global<WrapperConfig>(@hoglet_wrap_v1_to_da);
        assert!(
            smart_table::contains(&config.wrapped_tokens, v2_token_addr),
            error::not_found(E_TOKEN_NOT_WRAPPED)
        );
        let token_id = smart_table::borrow(&config.wrapped_tokens, v2_token_addr);
        tokenv1::get_token_id_fields(token_id)
    }

    #[view]
    public fun get_wrapped_collection_info(v2_collection_addr: address): (address, String) acquires WrappedCollectionMeta {
        assert!(exists<WrappedCollectionMeta>(v2_collection_addr), error::not_found(E_COLLECTION_NOT_WRAPPED));
        let meta = borrow_global<WrappedCollectionMeta>(v2_collection_addr);
        (meta.v1_creator, meta.v1_collection_name)
    }
}
