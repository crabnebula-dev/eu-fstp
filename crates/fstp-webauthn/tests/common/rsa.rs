//! A synthetic RS256 test vector.
//!
//! The key is an RSA-2048 key made for these tests only. Its private half
//! is not kept. The signature is RSASSA-PKCS1-v1_5 with SHA-256 over the
//! assertion of `authn::Asn::valid(1)`: authenticator data for
//! `authn::HOST` with UP and UV and counter 1, then SHA-256 of the
//! client data JSON for `authn::CHALLENGE`. fstp-crypto verifies RS256
//! but does not sign it, so the vector is fixed.

/// The modulus, 2048 bits.
pub(crate) const N: &str = "c14434d2748e569bb15325d3023a0ea9b51a79ecdc8b76b897fe0e210f383e934885c013863b801a8285819254d9e1078466288c1a58b3545f0b91571537cd11ea3479aaf0e5f1a18dff3cf1294a34967a5e98473c3dee8460f7ce50c18003e5a560de3842e33128b3b562a750f45e5490c16a3b4cbc0b0998548f0fb9eff16753a77c9e2a550d23fdb40c94a73aa3ec010013e862657d94ff0cf6ffe0e247353a7658eeae8330ca9f34c00408ca6e9676d318d742cb16dcd4b4311eb470f6618a12bc0c4921d5d457d3f36e750d937c476764e301e8db524e2a3f989d3d784fc24b79d433517f24aa6ebbb1883e2a1f36446c317635cad96facacf7bf9a53cd";

/// The public exponent 65537.
pub(crate) const E: [u8; 3] = [0x01, 0x00, 0x01];

/// The authenticator data the signature covers.
pub(crate) const AUTH_DATA: &str =
    "5c9c1955325b816e41f2e3afc7178fc2be6f219d266928c43ebfeab5ff962eb30500000001";

/// The client data JSON the signature covers.
pub(crate) const CLIENT_DATA: &str = "{\"type\":\"webauthn.get\",\"challenge\":\"UlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlI\",\"origin\":\"https://c0ffee.cells.fstp.example\",\"crossOrigin\":false}";

/// The signature.
pub(crate) const SIGNATURE: &str = "c121b6af0edbb98eecfb9f58df8bc02a31fa59cdc3b7d2c4d5d75c17377d631edb55a03f5d6b3483a038752ecc377f3da0fc19f406532c550f89cdfee0ab9a92be0a382b3ee8e09ba924f42ce7eaf2018c05462e2d8266d940a2ea634257639b8c973a14191cb152b492ab161ce7fc8dec386b8d954119c5c784b24947ebb41b1e29c50b90dd18d18e4612746d117672abc8783b62d373f6cd3c0e574abb74e5a483ea9c1dfcb11b8d83cb9947171cbf8e1da6379eddcca6bc3824280dd82af5c5ab0bb280e5e059a85bf2c1d033862af439fda7a3ddc82f1ed568b32a163c2f6330e08b5d7aa266eb96b9dac5d86c53c82e94075d8110d7457a0b82f9361c84";
