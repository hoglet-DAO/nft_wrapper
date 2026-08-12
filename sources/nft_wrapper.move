module hoglet_wrap_v1_to_da::nft_wrapper {
    use std::signer;
    use std::bcs;
    use std::string::{Self, String};
    use std::option;
    use std::vector;
    use supra_framework::object::{Self, Object};
    use supra_framework::account;
    use aptos_std::smart_table::{Self, SmartTable};
    use aptos_std::error;
    use aptos_token_objects::token::{Self, Token, BurnRef};
    use aptos_token_objects::collection;
    use aptos_token_objects::royalty;
    use aptos_token::token as tokenv1;

    const ERR_NOT_INITIALIZED: u64 = 1;
    const ERR_NOT_OWNER: u64 = 2;
    const ERR_COLLECTION_NAME_TOO_LONG: u64 = 3;
    const ERR_AMOUNT_MUST_BE_ONE: u64 = 4;

    struct WrapperConfig has key {
        treasury_cap: account::SignerCapability,
        // Maps the V2 Object Address -> V1 TokenId
        wrapped_tokens: SmartTable<address, tokenv1::TokenId>,
        // Keeps track of initiated collections to prevent double creation
        initiated_collections: SmartTable<String, bool>,
        // Stores BurnRef per wrapped token to guarantee burn capability
        burn_refs: SmartTable<address, BurnRef>,
    }

    fun init_module(account: &signer) {
        let (_resource_signer, resource_cap) = account::create_resource_account(account, bcs::to_bytes(&string::utf8(b"NFT_WRAPPER_VAULT_V2")));
        move_to(account, WrapperConfig {
            treasury_cap: resource_cap,
            wrapped_tokens: smart_table::new(),
            initiated_collections: smart_table::new(),
            burn_refs: smart_table::new(),
        });
    }

    fun address_to_hex_string(addr: address): String {
        let addr_bytes = bcs::to_bytes(&addr);
        let hex_bytes = vector::empty<u8>();
        let hex_chars = b"0123456789abcdef";
        let i = 0;
        let len = vector::length(&addr_bytes);
        while (i < len) {
            let byte = *vector::borrow(&addr_bytes, i);
            vector::push_back(&mut hex_bytes, *vector::borrow(&hex_chars, (byte >> 4 as u64)));
            vector::push_back(&mut hex_bytes, *vector::borrow(&hex_chars, ((byte & 0x0F) as u64)));
            i = i + 1;
        };
        string::utf8(hex_bytes)
    }

    // Helper to generate a unique string for a V1 collection
    fun get_wrapped_collection_name(creator: address, collection: String): String {
        let hash = string::utf8(b"w_");
        string::append(&mut hash, address_to_hex_string(creator));
        string::append(&mut hash, string::utf8(b"_"));
        string::append(&mut hash, collection);
        hash
    }

    public fun get_wrapped_collection_address(creator: address, collection_name: String): address acquires WrapperConfig {
        let config = borrow_global<WrapperConfig>(@hoglet_wrap_v1_to_da);
        let vault_signer = account::create_signer_with_capability(&config.treasury_cap);
        let vault_addr = signer::address_of(&vault_signer);
        
        let mut_collection_name = get_wrapped_collection_name(creator, collection_name);
        collection::create_collection_address(&vault_addr, &mut_collection_name)
    }

    // Internal function to ensure the V2 collection exists automatically
    fun init_collection_if_needed(
        config: &mut WrapperConfig,
        token_id: tokenv1::TokenId
    ) {
        let (creator_address, collection_name, _token_name, _property_version) = tokenv1::get_token_id_fields(&token_id);
        let hash = get_wrapped_collection_name(creator_address, collection_name);
        
        if (smart_table::contains(&config.initiated_collections, hash)) {
            return
        };

        let vault_signer = account::create_signer_with_capability(&config.treasury_cap);
        
        assert!(string::length(&hash) <= 128, error::invalid_argument(ERR_COLLECTION_NAME_TOO_LONG));

        // Create V2 collection using DA standard directly (returns ConstructorRef)
        let _collection_ref = collection::create_unlimited_collection(
            &vault_signer,
            tokenv1::get_collection_description(creator_address, collection_name),
            hash,
            option::none<royalty::Royalty>(),
            tokenv1::get_collection_uri(creator_address, collection_name),
        );

        smart_table::add(&mut config.initiated_collections, hash, true);
    }

    /// Takes a V1 Token struct, locks it, and returns a V2 Object transferred to the user
    public fun wrap_v1_to_da(user: &signer, v1_token: tokenv1::Token): Object<Token> acquires WrapperConfig {
        let config = borrow_global_mut<WrapperConfig>(@hoglet_wrap_v1_to_da);
        let token_id = tokenv1::get_token_id(&v1_token);

        // Validate: only NFTs with amount == 1 (prevent semi-fungible token loss)
        assert!(tokenv1::get_token_amount(&v1_token) == 1, error::invalid_argument(ERR_AMOUNT_MUST_BE_ONE));
        
        // Ensure V2 collection is created automatically
        init_collection_if_needed(config, token_id);

        let vault_signer = account::create_signer_with_capability(&config.treasury_cap);

        // LOCK: Deposit V1 token struct into vault's TokenStore
        tokenv1::deposit_token(&vault_signer, v1_token);

        let token_data = tokenv1::get_tokendata_id(token_id);
        let (creator_address, collection_name, token_name, _property_version) = tokenv1::get_token_id_fields(&token_id);
        let mut_collection_name = get_wrapped_collection_name(creator_address, collection_name);

        // MINT: Create V2 token using DA standard directly (returns ConstructorRef)
        let constructor_ref = token::create(
            &vault_signer,
            mut_collection_name,
            tokenv1::get_tokendata_description(token_data),
            token_name,
            option::none<royalty::Royalty>(),
            tokenv1::get_tokendata_uri(creator_address, token_data),
        );

        // Get address directly from ConstructorRef no GUID prediction needed
        let minted_token_addr = object::address_from_constructor_ref(&constructor_ref);

        // Store BurnRef to guarantee we can always burn this token
        let burn_ref = token::generate_burn_ref(&constructor_ref);
        smart_table::add(&mut config.burn_refs, minted_token_addr, burn_ref);

        let minted_token = object::address_to_object<Token>(minted_token_addr);
        
        // SAVE STATE: Map V2 object to V1 TokenId
        smart_table::add(&mut config.wrapped_tokens, minted_token_addr, token_id);

        // Transfer ownership of the minted V2 object to the user
        let user_addr = signer::address_of(user);
        object::transfer(&vault_signer, minted_token, user_addr);

        // RETURN V2 to caller (router/staking module)
        minted_token
    }

    /// Takes a V2 Object, burns it, and returns the original V1 Token struct
    public fun unwrap_da_to_v1(user: &signer, v2_token: Object<Token>): tokenv1::Token acquires WrapperConfig {
        let user_addr = signer::address_of(user);
        assert!(object::owner(v2_token) == user_addr, error::permission_denied(ERR_NOT_OWNER));

        let v2_token_addr = object::object_address(&v2_token);
        let config = borrow_global_mut<WrapperConfig>(@hoglet_wrap_v1_to_da);

        // GET V1 TOKEN ID
        let token_id = *smart_table::borrow(&config.wrapped_tokens, v2_token_addr);

        // BURN V2 TOKEN using stored BurnRef (guaranteed to work)
        let burn_ref = smart_table::remove(&mut config.burn_refs, v2_token_addr);
        token::burn(burn_ref);
        smart_table::remove(&mut config.wrapped_tokens, v2_token_addr);

        // UNLOCK V1 TOKEN: Withdraw from vault and return as struct
        let vault_signer = account::create_signer_with_capability(&config.treasury_cap);
        tokenv1::withdraw_token(&vault_signer, token_id, 1)
    }

    #[view]
    public fun is_wrapped(v2_token_addr: address): bool acquires WrapperConfig {
        let config = borrow_global<WrapperConfig>(@hoglet_wrap_v1_to_da);
        smart_table::contains(&config.wrapped_tokens, v2_token_addr)
    }
}