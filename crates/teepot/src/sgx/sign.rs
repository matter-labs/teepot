// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023-2024 Matter Labs

// Copyright (c) The Enarx Project Developers https://github.com/enarx/sgx

//! SGX signature structures
//!
//! Mostly copied from the [`sgx`](https://crates.io/crates/sgx) crate,
//! but with some modifications to make it easier to use in a standalone context.
//!

use bytemuck::{bytes_of, Pod, Zeroable};
use num_integer::Integer;
use num_traits::ToPrimitive;
use rand::thread_rng;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, LineEnding},
    traits::PublicKeyParts,
    BigUint, Pkcs1v15Sign, RsaPrivateKey,
};
use sha2::Digest as _;
use sha2::Sha256;
pub use zeroize::Zeroizing;

/// Enclave CPU attributes
///
/// This type represents the CPU features turned on in an enclave.
#[repr(C, packed(4))]
#[derive(Copy, Clone, Debug, Pod, Zeroable)]
pub struct Attributes {
    features: u64,
    xfrm: u64,
}

/// The `Author` of an enclave
///
/// This structure encompasses the first block of fields from `SIGSTRUCT`
/// that is included in the signature. It is split out from `Signature`
/// in order to make it easy to hash the fields for the signature.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Pod)]
pub struct Author {
    header1: [u8; 16],
    vendor: u32,
    date: u32,
    header2: [u8; 16],
    swdefined: u32,
    reserved: [u32; 21],
}

unsafe impl Zeroable for Author {}

impl Author {
    const HEADER1: [u8; 16] = 0x06000000E10000000000010000000000u128.to_be_bytes();
    const HEADER2: [u8; 16] = 0x01010000600000006000000001000000u128.to_be_bytes();

    #[allow(clippy::unreadable_literal)]
    /// Creates a new Author from a date and software defined value.
    ///
    /// Note that the `date` input is defined in binary-coded decimal. For
    /// example, the unix epoch is: `0x1970_01_01`.
    pub const fn new(date: u32, swdefined: u32) -> Self {
        Self {
            header1: Self::HEADER1,
            vendor: 0,
            date,
            header2: Self::HEADER2,
            swdefined,
            reserved: [0; 21],
        }
    }

    /// get the date
    #[inline]
    pub fn date(&self) -> u32 {
        self.date
    }

    /// get the swdefined
    #[inline]
    pub fn swdefined(&self) -> u32 {
        self.swdefined
    }
}

/// The enclave signature body
///
/// This structure encompasses the second block of fields from `SIGSTRUCT`
/// that is included in the signature. It is split out from `Signature`
/// in order to make it easy to hash the fields for the signature.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Pod, Zeroable)]
pub struct Body {
    misc_select: u32,
    misc_mask: u32,
    cet_attr_select: u8,
    cet_attr_mask: u8,
    reserved0: [u8; 2],
    ext_fid: [u8; 16],
    attr_select: [u8; 16],
    attr_mask: [u8; 16],
    mrenclave: [u8; 32],
    reserved1: [u8; 16],
    ext_pid: [u8; 16],
    pid: u16,
    svn: u16,
}

impl Body {
    /// Check if the debug flag can be set
    #[inline]
    pub fn can_set_debug(&self) -> bool {
        /// Enables enclave debug mode
        ///
        /// This gives permission to use EDBGRD and EDBGWR to read and write
        /// enclave memory as plaintext, respectively. You most likely want
        /// to validate that this option is disabled during attestion.
        const DEBUG: u64 = 1 << 1;
        let attr_select: &Attributes = bytemuck::try_from_bytes(&self.attr_select).unwrap();
        let attr_mask: &Attributes = bytemuck::try_from_bytes(&self.attr_mask).unwrap();

        (attr_select.features & DEBUG) == 0 && (attr_mask.features & DEBUG) == 0
    }
}

/// A signature on an enclave
///
/// This structure encompasses the `SIGSTRUCT` structure from the SGX
/// documentation, renamed for ergonomics. The two portions of the
/// data that are included in the signature are further divided into
/// subordinate structures (`Author` and `Body`) for ease during
/// signature generation and validation.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Pod, Zeroable)]
pub struct Signature {
    author: Author,
    modulus: [u8; 384],
    exponent: u32,
    signature: [u8; 384],
    body: Body,
    reserved: [u8; 12],
    q1: [u8; 384],
    q2: [u8; 384],
}

impl Signature {
    /// Signs the supplied `author` and `body` with the specified `key`.
    pub fn new<T: PrivateKey>(key: &T, author: Author, body: Body) -> Result<Self, T::Error> {
        let a = bytes_of(&author);
        let b = bytes_of(&body);
        let sd = key.sign(a, b)?;

        Ok(Self {
            author,
            modulus: sd.modulus,
            exponent: sd.exponent,
            signature: sd.signature,
            body,
            reserved: [0; 12],
            q1: sd.q1,
            q2: sd.q2,
        })
    }

    /// Returns the author of the enclave.
    pub fn author(&self) -> Author {
        self.author
    }

    /// Returns the body of the enclave.
    pub fn body(&self) -> Body {
        self.body
    }
}

/// A detached enclave signature
pub struct SigData {
    /// The signature
    pub signature: [u8; 384],
    /// The public modulus
    pub modulus: [u8; 384],
    /// The public exponent
    pub exponent: u32,
    /// The first prime factor
    pub q1: [u8; 384],
    /// The second prime factor
    pub q2: [u8; 384],
}

/// A fixed-size hash
pub trait Digest: Sized {
    /// The output size of the hash
    type Output: AsRef<[u8]>;

    /// Construct a new hasher
    fn new() -> Self;
    /// Update the hasher with more data
    fn update(&mut self, bytes: &[u8]);
    /// Finalize the hasher and return the digest
    fn finish(self) -> Self::Output;

    /// Update the hasher with more data and return the hasher
    #[inline]
    fn chain(mut self, bytes: &[u8]) -> Self {
        self.update(bytes);
        self
    }
}

/// A private key used for signing an enclave
pub trait PrivateKey: Sized {
    /// The error type for this key
    type Error: core::fmt::Debug;

    /// Generate a new private key
    fn generate(exponent: u8) -> Result<Self, Self::Error>;

    /// Stringify the private key as a PEM-encoded string
    fn to_pem(&self) -> Result<Zeroizing<String>, Self::Error>;

    /// Load a private key from a PEM-encoded string
    fn from_pem(pem: &str) -> Result<Self, Self::Error>;
    /// Load a private key from a DER-encoded buffer
    fn from_der(der: &[u8]) -> Result<Self, Self::Error>;
    /// Sign the specified `author` and `body`
    fn sign(&self, author: &[u8], body: &[u8]) -> Result<SigData, Self::Error>;
}

fn arr_from_big(value: &BigUint) -> [u8; 384] {
    let mut arr = [0u8; 384];
    let buf = value.to_bytes_le();
    arr[..buf.len()].copy_from_slice(&buf);
    arr
}

/// SHA2-256
pub struct S256Digest(Sha256);

impl Digest for S256Digest {
    type Output = [u8; 32];

    #[inline]
    fn new() -> Self {
        Self(Sha256::new())
    }

    #[inline]
    fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes)
    }

    #[inline]
    fn finish(self) -> Self::Output {
        *self.0.finalize().as_ref()
    }
}

/// RSA w/ SHA2-256
pub struct RS256PrivateKey(RsaPrivateKey);

impl RS256PrivateKey {
    /// Create a new RSA private key.
    pub fn new(key: RsaPrivateKey) -> Self {
        assert!(key.n().bits() <= 384 * 8);
        Self(key)
    }
}

impl PrivateKey for RS256PrivateKey {
    type Error = rsa::errors::Error;

    fn generate(exponent: u8) -> Result<Self, Self::Error> {
        let mut rng = thread_rng();
        let exp = BigUint::from(exponent);
        let key = RsaPrivateKey::new_with_exp(&mut rng, 384 * 8, &exp)?;
        Ok(Self::new(key))
    }

    fn to_pem(&self) -> Result<Zeroizing<String>, Self::Error> {
        let pem = RsaPrivateKey::to_pkcs1_pem(&self.0, LineEnding::default())?;
        Ok(pem)
    }

    fn from_pem(pem: &str) -> Result<Self, Self::Error> {
        let key = RsaPrivateKey::from_pkcs1_pem(pem)?;
        Ok(Self::new(key))
    }

    fn from_der(der: &[u8]) -> Result<Self, Self::Error> {
        let key = RsaPrivateKey::from_pkcs1_der(der)?;
        Ok(Self::new(key))
    }

    fn sign(&self, author: &[u8], body: &[u8]) -> Result<SigData, Self::Error> {
        use sha2::digest::Update;

        let hash = Sha256::new().chain(author).chain(body).finalize();

        let padding = Pkcs1v15Sign::new::<Sha256>();
        let sig = self.0.sign(padding, &hash)?;

        // Calculate q1 and q2.
        let s = BigUint::from_bytes_be(&sig);
        let m = self.0.n();
        let (q1, qr) = (&s * &s).div_rem(m);
        let q2 = (&s * qr) / m;

        Ok(SigData {
            signature: arr_from_big(&s),
            modulus: arr_from_big(m),
            exponent: self.0.e().to_u32().unwrap(),
            q1: arr_from_big(&q1),
            q2: arr_from_big(&q2),
        })
    }
}

#[cfg(test)]
mod test {
    use super::{Author, Body, Signature};
    use testaso::testaso;

    testaso! {
        struct Author: 4, 128 => {
            header1: 0,
            vendor: 16,
            date: 20,
            header2: 24,
            swdefined: 40,
            reserved: 44
        }
        struct Body: 4, 128 => {
            misc_select: 0,
            misc_mask: 4,
            cet_attr_select: 8,
            cet_attr_mask: 9,
            reserved0: 10,
            ext_fid: 12,
            attr_select: 28,
            attr_mask: 44,
            mrenclave: 60,
            reserved1: 92,
            ext_pid: 108,
            pid: 124,
            svn: 126
        }
        struct Signature: 4, 1808 => {
            author: 0,
            modulus: 128,
            exponent: 512,
            signature: 516,
            body: 900,
            reserved: 1028,
            q1: 1040,
            q2: 1424
        }
    }

    #[test]
    #[allow(clippy::unusual_byte_groupings)]
    fn author_instantiation() {
        let author = Author::new(0x2000_03_30, 0u32);
        assert_eq!(author.header1, Author::HEADER1);
        assert_eq!(author.vendor, 0u32);
        assert_eq!(author.date, 0x2000_03_30);
        assert_eq!(author.header2, Author::HEADER2);
        assert_eq!(author.swdefined, 0u32);
        assert_eq!(author.reserved, [0; 21]);
    }

    #[test]
    fn test_signature() {
        let test_sig = include_bytes!("../../tests/data/gramine-test.sig");
        let sig: Signature = bytemuck::try_pod_read_unaligned(test_sig).unwrap();
        let body = sig.body();
        assert_eq!(
            body.mrenclave.to_vec(),
            hex::decode("f78170fe28e2e8671d83f5056975d25a27eb2c333dc520c2ccaf4de6b3f9c81b")
                .unwrap()
        );
        assert!(!body.can_set_debug());
        assert_eq!(body.misc_select, 1);
    }
}
