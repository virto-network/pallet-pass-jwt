# Pallet pass jwt and validator

## Overview
This pallet allows to permissionlessly register JWT Issuers, and publish the JWKs associated with them.

These JWKs would be used in conjunction with an Authenticator structure to verify the JWT-based attestations and credentials.

## Terminology
The following terminology is directly extracted (or interpreted) from IETF's [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) and [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) which defines JWKs and JWTs, and how they behave:

- **JWT**: JSON Web Token (JWT) is a compact, URL-safe means of representing claims to be transferred between two parties.
- **Issuer**: The issuer claim represents the party that issued a JWT.
- **JWK**: A JSON object that represents a cryptographic key. The members of the object represent properties of the key, including its value.

The following terminology is related to **FRAME** and **Pallet Pass** concepts:

- **AccountId**: A 32-byte array which serves to uniquely identify a single account in the runtime.
- **Authenticator**: A series of structures which support the mechanisms to help Pallet Pass to determine whether some given attestation (enrolment of a device onto an Account) or credentials (used to authenticate) are valid.
- **Session Key**: An `AccountId` which uniquely identifies a transient session tied to a Pass Account.
- Intrinsic Challenge: A challenge given by the runtime. Serves as a nonce to prevent replay attacks.

Finally, the following terminology is specific for

- **Owner**: Refers to the `AccountId` which created and has admin privileges to manage an Issuer.
- **Issuer**: An entity which issues `JWTs` and has an active `JWK Set` registered on chain.
- **Deposit**: An amount that the **Owner** reserves to support the existence of an Issuer.

## Goals
1. An **Owner** can `register` an **Issuer** with an unique `id` (limited to 256 bytes).
2. The **Owner** is able to `set_metadata` (`name`, `url`) for an **Issuer** which they own.
3. The **Owner** can `set_keys` for an existing **Issuer** which they own.
4. A `JWT` (limited to 1024 bytes) that is issued by an **Issuer** can be verified as an Attestation, or Credential if:
    - The value of the `iss` claim in the payload corresponds to the `id` of the **Issuer**.
    - The `alg` corresponds to a supported algorithm in the JWT validator crate.
    - The `kid` corresponds to an existing key in the registered `JWK Set` for that **Issuer**.
    - The *signature* of the `JWT` is valid for a given `JWK`.
5. Additionally, the `JWT` would be valid if these conditions are followed:
    - The `iat` and `exp` claims exist in the payload.
    - The `sub` claim exists. The length of the value is not important, since it'll be hashed to represent the `DeviceId`.
    - The `aud` claim exists. Its value must be a `URN` from which the `AuthorityId` can be obtained.
    - The `jti` claim exists. Its value must be either the SS58 address of a **Session Key**, or the Hash of the `Method`.
    - The `kreivo:challenge` claim exists. Its value must correspond to the (`Challenge`, `Context`) tuple derived from the **Intrinsic Challenge** value given by the runtime.
6. It is possible to `destroy` and `refund_deposit` for an existing **Issuer**. Once this is done, the `id` would be unable to be used again (to prevent attack vectors).

## Interface

### Dispatchable Functions

- `register`: Given an `origin`, and an `id`, registers a new **Issuer**. Reserves an amount defined by the `RegisterDeposit` configuration type from the origin's funds.
- `set_metadata`: Given an `origin` which owns the **Issuer** identified by `id`, can set name and url metadata values. Reserves an amount defined by the `MetadataDepositBase` and `MetadataDepositBytes` configuration types from the origin's funds.
- `set_keys`: Given an `origin`, which owns the **Issuer** identified by `id`, can set or overwrite (rotate) a vector of **Keys** that represent the set of currently valid JWKs. Reserves an amount defined by the `KeyDepositBase`, and `KeyDepositBytes` configuration types from the origin's funds. 
> Suggestion: Define the internal storage of the keys (i.e. IssuerKeys type) to be represented by a StorageDoubleMap of (IssuerId, KeyId) and a value of type KeyValue, where KeyValue can be an enum that represents the public keys in the least amount possible. We must define limits for the KeyId. The suggested enum structure can be defined in the verifier to work alongside the verification mechanism in that crate.

- `destroy`: Given an `origin` which owns the **Issuer** identified by `id`, can clear the key set and destroy **Issuer**, refunding the reserved funds. The **Issuer** is then cleared of an owner, but not destroyed, to prevent this destruction becoming an attack vector.
>Suggestion: Define the **Issuer** storage type as StorageMap of **IssuerId**, and value of Option<(AccountId, Balance)> to define the owner and the reserved amount (if any owner, whatsoever). That way, destroying an **Issuer** means just changing the value for the **Issuer** to None.

## Authenticators
See [Goals](#goals) to better understand how Attestation (a.k.a. JWTAttestation) and Credentials (a.k.a. JWT) structures should be defined.

## Related modules
- [pallet pass](https://hackmd.io/iVwkY1wKTgWpP6DoQAUpyg)
