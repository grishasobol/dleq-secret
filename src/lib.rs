#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT as G, ristretto::CompressedRistretto};
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sha2::{Digest, Sha512};

#[cfg(feature = "std")]
use rand_core::{OsRng, RngCore};

pub use curve25519_dalek::ristretto::RistrettoPoint;
pub use curve25519_dalek::scalar::Scalar;

const DOMAIN: &[u8] = b"nizk:elgamal-plaintext-equality:v1";
const KDF_LABEL: &[u8] = b"KDF:v1:sym-from-M";

#[derive(Clone, Debug)]
pub struct PK(pub RistrettoPoint);

impl Encode for PK {
    fn encode(&self) -> Vec<u8> {
        self.0.compress().as_bytes().to_vec()
    }
}

impl Decode for PK {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        decode_point(input).map(PK)
    }
}

impl TypeInfo for PK {
    type Identity = Self;

    fn type_info() -> scale_info::Type {
        scale_info::Type::builder()
            .path(scale_info::Path::new("PK", module_path!()))
            .composite(scale_info::build::Fields::unnamed())
    }
}

// ---------- utilities ----------
#[cfg(feature = "std")]
fn random_scalar() -> Scalar {
    let mut rng = OsRng;
    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn hash32(label: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(label);
    h.update(data);
    let digest = h.finalize(); // 64 bytes
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

fn xor_in_place(buf: &mut [u8], key: &[u8]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b ^= key[i % key.len()];
    }
}

fn hash_to_scalar(domain_sep: &[u8], items: &[&[u8]]) -> Scalar {
    let mut h = Sha512::new();
    h.update(domain_sep);
    for it in items {
        h.update(it);
    }
    let digest = h.finalize(); // 64 bytes
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

// ---------- keypairs ----------
#[derive(Clone, Debug)]
pub struct Keypair {
    pub sk: Scalar,
    pub pk: RistrettoPoint,
}

#[cfg(feature = "std")]
pub fn gen_keypair() -> Keypair {
    let sk = random_scalar();
    let pk = sk * G;
    Keypair { sk, pk }
}

// ---------- ElGamal over points in Ristretto (message M is a point) ----------
// Encrypt point M under pk:
//   C1 = r*G
//   C2 = M + r*pk
// Decrypt with sk:
//   M = C2 - sk*C1
#[derive(Clone, Debug)]
pub struct ElGamalPointCipher {
    pub c1: RistrettoPoint,
    pub c2: RistrettoPoint,
}

impl Encode for ElGamalPointCipher {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.c1.compress().as_bytes());
        out.extend_from_slice(self.c2.compress().as_bytes());
        out
    }
}

impl Decode for ElGamalPointCipher {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        let c1 = decode_point(input)?;
        let c2 = decode_point(input)?;

        Ok(ElGamalPointCipher { c1, c2 })
    }
}

#[cfg(feature = "std")]
fn elgamal_encrypt_point(pk: RistrettoPoint, m: RistrettoPoint) -> (ElGamalPointCipher, Scalar) {
    let r = random_scalar();
    let c1 = r * G;
    let c2 = m + r * pk;
    (ElGamalPointCipher { c1, c2 }, r)
}

fn elgamal_decrypt_point(sk: Scalar, ct: &ElGamalPointCipher) -> RistrettoPoint {
    ct.c2 - sk * ct.c1
}

// ---------- NIZK proof: "two ElGamal ciphertexts encrypt the same plaintext" ----------
//
// We will represent M as M = m*G for some scalar m.
// Prover knows (m, r, s) such that:
//
//   U1 = r*G
//   U2 = m*G + r*PkX
//   V1 = s*G
//   V2 = m*G + s*Pk1
//
// Commit with random (rm, rr, rs):
//   T1 = rr*G
//   T2 = rm*G + rr*PkX
//   T3 = rs*G
//   T4 = rm*G + rs*Pk1
//
// Challenge c = H(transcript)
// Responses:
//   z_m = rm + c*m
//   z_r = rr + c*r
//   z_s = rs + c*s
//
// Verify:
//   z_r*G == T1 + c*U1
//   z_m*G + z_r*PkX == T2 + c*U2
//   z_s*G == T3 + c*V1
//   z_m*G + z_s*Pk1 == T4 + c*V2
//
#[derive(Clone, Debug)]
pub struct PlaintextEqProof {
    pub t1: RistrettoPoint,
    pub t2: RistrettoPoint,
    pub t3: RistrettoPoint,
    pub t4: RistrettoPoint,
    pub z_m: Scalar,
    pub z_r: Scalar,
    pub z_s: Scalar,
}

impl Encode for PlaintextEqProof {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.t1.compress().as_bytes());
        out.extend_from_slice(self.t2.compress().as_bytes());
        out.extend_from_slice(self.t3.compress().as_bytes());
        out.extend_from_slice(self.t4.compress().as_bytes());
        out.extend_from_slice(self.z_m.as_bytes());
        out.extend_from_slice(self.z_r.as_bytes());
        out.extend_from_slice(self.z_s.as_bytes());
        out
    }
}

impl Decode for PlaintextEqProof {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        let t1 = decode_point(input)?;
        let t2 = decode_point(input)?;
        let t3 = decode_point(input)?;
        let t4 = decode_point(input)?;

        let mut z_m_bytes = [0u8; 32];
        input.read(z_m_bytes.as_mut_slice())?;
        let z_m = Scalar::from_canonical_bytes(z_m_bytes)
            .expect("invalid scalar for z_m in plaintext equality proof");

        let mut z_r_bytes = [0u8; 32];
        input.read(z_r_bytes.as_mut_slice())?;
        let z_r = Scalar::from_canonical_bytes(z_r_bytes)
            .expect("invalid scalar for z_r in plaintext equality proof");

        let mut z_s_bytes = [0u8; 32];
        input.read(z_s_bytes.as_mut_slice())?;
        let z_s = Scalar::from_canonical_bytes(z_s_bytes)
            .expect("invalid scalar for z_s in plaintext equality proof");

        Ok(PlaintextEqProof {
            t1,
            t2,
            t3,
            t4,
            z_m,
            z_r,
            z_s,
        })
    }
}

#[cfg(feature = "std")]
fn prove_plaintext_equality(
    domain: &[u8],
    pk_xkey: RistrettoPoint, // Xkey.pk
    pk1: RistrettoPoint,     // user1 pk
    ck: &ElGamalPointCipher, // U1,U2 under pk_xkey
    dk: &ElGamalPointCipher, // V1,V2 under pk1
    m: Scalar,               // secret scalar for M = m*G
    r: Scalar,               // randomness for ck
    s: Scalar,               // randomness for dk
) -> PlaintextEqProof {
    // randomness
    let rm = random_scalar();
    let rr = random_scalar();
    let rs = random_scalar();

    // commitments
    let t1 = rr * G;
    let t2 = rm * G + rr * pk_xkey;
    let t3 = rs * G;
    let t4 = rm * G + rs * pk1;

    // Fiat–Shamir challenge
    let c = hash_to_scalar(
        domain,
        &[
            G.compress().as_bytes(),
            pk_xkey.compress().as_bytes(),
            pk1.compress().as_bytes(),
            ck.c1.compress().as_bytes(),
            ck.c2.compress().as_bytes(),
            dk.c1.compress().as_bytes(),
            dk.c2.compress().as_bytes(),
            t1.compress().as_bytes(),
            t2.compress().as_bytes(),
            t3.compress().as_bytes(),
            t4.compress().as_bytes(),
        ],
    );

    let z_m = rm + c * m;
    let z_r = rr + c * r;
    let z_s = rs + c * s;

    PlaintextEqProof {
        t1,
        t2,
        t3,
        t4,
        z_m,
        z_r,
        z_s,
    }
}

fn verify_plaintext_equality(
    domain: &[u8],
    pk_xkey: RistrettoPoint,
    pk1: RistrettoPoint,
    ck: &ElGamalPointCipher,
    dk: &ElGamalPointCipher,
    proof: &PlaintextEqProof,
) -> bool {
    let c = hash_to_scalar(
        domain,
        &[
            G.compress().as_bytes(),
            pk_xkey.compress().as_bytes(),
            pk1.compress().as_bytes(),
            ck.c1.compress().as_bytes(),
            ck.c2.compress().as_bytes(),
            dk.c1.compress().as_bytes(),
            dk.c2.compress().as_bytes(),
            proof.t1.compress().as_bytes(),
            proof.t2.compress().as_bytes(),
            proof.t3.compress().as_bytes(),
            proof.t4.compress().as_bytes(),
        ],
    );

    // 1) z_r*G == T1 + c*U1
    let lhs1 = proof.z_r * G;
    let rhs1 = proof.t1 + c * ck.c1;

    // 2) z_m*G + z_r*PkX == T2 + c*U2
    let lhs2 = proof.z_m * G + proof.z_r * pk_xkey;
    let rhs2 = proof.t2 + c * ck.c2;

    // 3) z_s*G == T3 + c*V1
    let lhs3 = proof.z_s * G;
    let rhs3 = proof.t3 + c * dk.c1;

    // 4) z_m*G + z_s*Pk1 == T4 + c*V2
    let lhs4 = proof.z_m * G + proof.z_s * pk1;
    let rhs4 = proof.t4 + c * dk.c2;

    lhs1 == rhs1 && lhs2 == rhs2 && lhs3 == rhs3 && lhs4 == rhs4
}

// ---------- protocol structs ----------
#[derive(Clone, Debug)]
pub struct PublicData {
    pub pk_xkey: RistrettoPoint,              // Xkey.pk
    pub enc_m_under_xkey: ElGamalPointCipher, // C_K: encrypts M under pk_xkey
    pub enc_x: Vec<u8>,                       // CT_X: X encrypted under K=H(M)
}

impl Encode for PublicData {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.pk_xkey.compress().as_bytes());
        out.extend_from_slice(self.enc_m_under_xkey.c1.compress().as_bytes());
        out.extend_from_slice(self.enc_m_under_xkey.c2.compress().as_bytes());
        out.extend_from_slice(&self.enc_x);
        out
    }
}

fn decode_point<I: parity_scale_codec::Input>(
    input: &mut I,
) -> Result<RistrettoPoint, parity_scale_codec::Error> {
    let mut point_buff = [0u8; 32];
    input.read(point_buff.as_mut_slice())?;
    CompressedRistretto::from_slice(point_buff.as_slice())
        .map_err(|_| "cannot create compressed Ristretto point from bytes")?
        .decompress()
        .ok_or("cannot decompress point as valid Ristretto point")
        .map_err(Into::into)
}

impl Decode for PublicData {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        let pk_xkey = decode_point(input)?;
        let c1 = decode_point(input)?;
        let c2 = decode_point(input)?;

        let enc_m_under_xkey = ElGamalPointCipher { c1, c2 };

        let enc_message_len = input
            .remaining_len()?
            .ok_or("cannot decode enc_x: length is unknown")?;
        let mut enc_x = alloc::vec![0u8; enc_message_len as usize];
        input.read(enc_x.as_mut_slice())?;

        Ok(PublicData {
            pk_xkey,
            enc_m_under_xkey,
            enc_x,
        })
    }
}

impl TypeInfo for PublicData {
    type Identity = Self;

    fn type_info() -> scale_info::Type {
        scale_info::Type::builder()
            .path(scale_info::Path::new("PublicData", module_path!()))
            .composite(
                scale_info::build::Fields::named()
                    .field(|f| f.name("pk_xkey").ty::<PK>())
                    .field(|f| f.name("enc_m_under_xkey").ty::<(PK, PK)>())
                    .field(|f| f.name("enc_x").ty::<Vec<u8>>()),
            )
    }
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct GrantWithProof {
    pub enc_m_under_pk: ElGamalPointCipher, // D_K: encrypts same M under pk1
    pub proof_eq: PlaintextEqProof,         // NIZK: both ciphertexts encrypt same M
}

impl GrantWithProof {
    pub fn verify(&self, published: &PublicData, pk: RistrettoPoint) -> bool {
        verify_plaintext_equality(
            DOMAIN,
            published.pk_xkey,
            pk,
            &published.enc_m_under_xkey,
            &self.enc_m_under_pk,
            &self.proof_eq,
        )
    }

    pub fn decrypt_message(&self, public_data: &PublicData, sk: Scalar) -> Vec<u8> {
        let m_recovered = elgamal_decrypt_point(sk, &self.enc_m_under_pk);
        let k1 = hash32(KDF_LABEL, m_recovered.compress().as_bytes());
        let mut x_dec = public_data.enc_x.clone();
        xor_in_place(&mut x_dec, &k1);

        x_dec
    }
}

#[cfg(feature = "std")]
pub struct PreProof {
    xkey_pk: RistrettoPoint,
    enc_m_under_xkey: ElGamalPointCipher,
    m: Scalar,
    r: Scalar,
}

#[cfg(feature = "std")]
impl PreProof {
    pub fn proof_for_pk(&self, pk: RistrettoPoint) -> GrantWithProof {
        let (enc_m_under_pk, s) = elgamal_encrypt_point(pk, self.m * G);

        let proof_eq = prove_plaintext_equality(
            DOMAIN,
            self.xkey_pk,
            pk,
            &self.enc_m_under_xkey,
            &enc_m_under_pk,
            self.m,
            self.r,
            s,
        );

        let grant = GrantWithProof {
            enc_m_under_pk,
            proof_eq,
        };

        grant
    }
}

#[cfg(feature = "std")]
pub fn pre_proof_and_public_for_message(message: &[u8]) -> (PublicData, PreProof) {
    // One-time keypair Xkey used only as a *public key* for committing to M
    let xkey = gen_keypair(); // (skx, pk_xkey)

    // Secret message/key material M = m*G (kept secret)
    let m = random_scalar();
    let m_point = m * G;

    let k = hash32(KDF_LABEL, m_point.compress().as_bytes());
    let mut encrypted_message = message.to_vec();
    xor_in_place(&mut encrypted_message, &k);

    let (enc_m_under_xkey, r) = elgamal_encrypt_point(xkey.pk, m_point);

    let publish = PublicData {
        pk_xkey: xkey.pk,
        enc_m_under_xkey: enc_m_under_xkey.clone(),
        enc_x: encrypted_message,
    };

    (
        publish,
        PreProof {
            xkey_pk: xkey.pk,
            enc_m_under_xkey,
            m,
            r,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dleq() {
        let user1 = gen_keypair(); // (sk1, pk1)

        let message = b"Top secret payload X: only user1 must read this.".to_vec();
        let (public_data, pre_proof) = pre_proof_and_public_for_message(&message);

        let grant = pre_proof.proof_for_pk(user1.pk);

        // ---------------- Arbiter verification (no secrets revealed) ----------------
        let arbiter_ok = grant.verify(&public_data, user1.pk);
        assert!(arbiter_ok);

        // ---------------- User1 decrypts M, derives K, decrypts X ----------------
        let decrypted_message = grant.decrypt_message(&public_data, user1.sk);
        assert_eq!(decrypted_message, message);

        // ---------------- Cheating attempt: send wrong ciphertext to user1 ----------------
        // user2 sends encryption of M' != M under pk1, but reuses proof -> arbiter must reject
        let m2 = random_scalar();
        let m2_point = m2 * G;
        let (wrong_enc_under_pk1, _s2) = elgamal_encrypt_point(user1.pk, m2_point);

        let cheating_grant = GrantWithProof {
            enc_m_under_pk: wrong_enc_under_pk1,
            proof_eq: grant.proof_eq.clone(),
        };

        let arbiter_ok2 = cheating_grant.verify(&public_data, user1.pk); // should be false
        assert!(!arbiter_ok2);

        let decrypted_message2 = cheating_grant.decrypt_message(&public_data, user1.sk);
        assert_ne!(decrypted_message2, message);

        // ---------------- Cheating attempt: sends for other pk ----------------
        let alice = gen_keypair();
        let grant = pre_proof.proof_for_pk(alice.pk);

        let arbiter_ok3 = grant.verify(&public_data, user1.pk); // should be false
        assert!(!arbiter_ok3);

        let decrypted_message3 = grant.decrypt_message(&public_data, user1.sk);
        assert_ne!(decrypted_message3, message);

        // ---------------- Cheating attempt: sends proof for wrong message ----------------
        let other_message = b"Some other message Y".to_vec();
        let (_, other_pre_proof) = pre_proof_and_public_for_message(&other_message);
        let grant = other_pre_proof.proof_for_pk(user1.pk);

        let arbiter_ok4 = grant.verify(&public_data, user1.pk); // should be false
        assert!(!arbiter_ok4);

        let decrypted_message4 = grant.decrypt_message(&public_data, user1.sk);
        assert_ne!(decrypted_message4, message);
    }
}
