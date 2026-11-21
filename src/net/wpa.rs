//! WPA2-Personal (RSN with CCMP and a pre-shared key): the key hierarchy, the
//! EAPOL-Key frames of the 4-way handshake and the CCMP encapsulation of
//! frames, as IEEE 802.11 defines them.
//!
//! A CCMP-protected MPDU is its header (Protected bit set), the 8-byte CCMP
//! header (PN0, PN1, 0, key ID << 6 | ExtIV, PN2..PN5), the encrypted body and
//! an 8-byte MIC. [`seal`] encrypts an MPDU that already holds its CCMP header,
//! as the chip's MAC does with what its driver prepares; [`open`] checks and
//! decrypts one, keeping the CCMP header.

use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use hmac::{Hmac, Mac as _};
use sha1::Sha1;

use super::ieee80211::{self as wlan, Mac};

/// The RSN element body of a WPA2-Personal network: version 1, CCMP group and
/// pairwise ciphers, PSK key management, no capabilities.
pub const RSN: [u8; 20] = [
    1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 2, 0, 0,
];
/// Cipher suite and AKM suite selectors.
const SUITE_CCMP: [u8; 4] = [0x00, 0x0f, 0xac, 4];
const SUITE_PSK: [u8; 4] = [0x00, 0x0f, 0xac, 2];

pub const CCMP_HEADER: usize = 8;
pub const CCMP_MIC: usize = 8;
/// ExtIV bit of the key ID octet.
const EXT_IV: u8 = 0x20;

pub const ETHERTYPE_EAPOL: u16 = 0x888e;

/// Key information bits of an EAPOL-Key frame.
pub const KI_VERSION_AES: u16 = 2;
pub const KI_PAIRWISE: u16 = 1 << 3;
pub const KI_INSTALL: u16 = 1 << 6;
pub const KI_ACK: u16 = 1 << 7;
pub const KI_MIC: u16 = 1 << 8;
pub const KI_SECURE: u16 = 1 << 9;
pub const KI_ENCRYPTED: u16 = 1 << 12;

/// Offsets in an EAPOL frame (from its version octet) holding an EAPOL-Key.
const EAPOL_HEADER: usize = 4;
const KEY_INFO: usize = 5;
const KEY_REPLAY: usize = 9;
const KEY_NONCE: usize = 17;
const KEY_RSC: usize = 65;
const KEY_MIC: usize = 81;
const KEY_DATA_LEN: usize = 97;
const KEY_DATA: usize = 99;

fn hmac_sha1(key: &[u8], parts: &[&[u8]]) -> [u8; 20] {
    let mut m = <Hmac<Sha1> as hmac::Mac>::new_from_slice(key).expect("HMAC takes any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// The pairwise master key of a passphrase (8 to 63 characters) on an SSID:
/// PBKDF2-HMAC-SHA1, 4096 rounds, 32 bytes.
pub fn pmk(passphrase: &str, ssid: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    pbkdf2::pbkdf2_hmac::<Sha1>(passphrase.as_bytes(), ssid, 4096, &mut out);
    out
}

/// PRF-n: HMAC-SHA1 of the label, a zero octet, the data and a counter octet,
/// for counters 0, 1, ... until `out` is full.
pub fn prf(key: &[u8], label: &[u8], data: &[u8], out: &mut [u8]) {
    for (i, chunk) in out.chunks_mut(20).enumerate() {
        let block = hmac_sha1(key, &[label, &[0], data, &[i as u8]]);
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
}

/// The pairwise transient key and its parts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ptk {
    /// Key confirmation key: the MIC of EAPOL-Key frames.
    pub kck: [u8; 16],
    /// Key encryption key: the key data of EAPOL-Key frames.
    pub kek: [u8; 16],
    /// Temporal key: CCMP.
    pub tk: [u8; 16],
}

impl Ptk {
    /// PRF-384 of the PMK over both addresses and both nonces, each pair in
    /// increasing order.
    pub fn derive(
        pmk: &[u8; 32],
        aa: &Mac,
        spa: &Mac,
        anonce: &[u8; 32],
        snonce: &[u8; 32],
    ) -> Self {
        let mut data = Vec::with_capacity(76);
        data.extend_from_slice(aa.min(spa));
        data.extend_from_slice(aa.max(spa));
        data.extend_from_slice(anonce.min(snonce));
        data.extend_from_slice(anonce.max(snonce));
        let mut ptk = [0u8; 48];
        prf(pmk, b"Pairwise key expansion", &data, &mut ptk);
        Ptk {
            kck: ptk[..16].try_into().unwrap(),
            kek: ptk[16..32].try_into().unwrap(),
            tk: ptk[32..].try_into().unwrap(),
        }
    }
}

/// Whether the body of an RSN element offers CCMP and PSK, the only ones the
/// access point takes.
pub fn rsn_is_ccmp_psk(rsn: &[u8]) -> bool {
    let suites = |at: usize| -> Option<(Vec<[u8; 4]>, usize)> {
        let n = u16::from_le_bytes([*rsn.get(at)?, *rsn.get(at + 1)?]) as usize;
        let list = (0..n)
            .map(|i| rsn.get(at + 2 + 4 * i..at + 6 + 4 * i)?.try_into().ok())
            .collect::<Option<Vec<[u8; 4]>>>()?;
        Some((list, at + 2 + 4 * n))
    };
    let group = rsn.get(2..6);
    let Some((pairwise, at)) = suites(6) else {
        return false;
    };
    let Some((akm, _)) = suites(at) else {
        return false;
    };
    rsn.get(..2) == Some(&[1, 0])
        && group == Some(&SUITE_CCMP[..])
        && pairwise.contains(&SUITE_CCMP)
        && akm.contains(&SUITE_PSK)
}

/// An EAPOL-Key frame (descriptor type 2, RSN).
#[derive(Clone, Debug)]
pub struct EapolKey<'a> {
    pub info: u16,
    pub replay: u64,
    pub nonce: [u8; 32],
    pub mic: [u8; 16],
    pub data: &'a [u8],
}

impl<'a> EapolKey<'a> {
    /// `eapol` is the EAPOL PDU, from its version octet.
    pub fn parse(eapol: &'a [u8]) -> Option<Self> {
        // type 3: EAPOL-Key; descriptor 2: RSN
        if eapol.len() < KEY_DATA || eapol[1] != 3 || eapol[4] != 2 {
            return None;
        }
        let len = u16::from_be_bytes([eapol[KEY_DATA_LEN], eapol[KEY_DATA_LEN + 1]]) as usize;
        Some(EapolKey {
            info: u16::from_be_bytes([eapol[KEY_INFO], eapol[KEY_INFO + 1]]),
            replay: u64::from_be_bytes(eapol[KEY_REPLAY..KEY_REPLAY + 8].try_into().unwrap()),
            nonce: eapol[KEY_NONCE..KEY_NONCE + 32].try_into().unwrap(),
            mic: eapol[KEY_MIC..KEY_MIC + 16].try_into().unwrap(),
            data: eapol.get(KEY_DATA..KEY_DATA + len)?,
        })
    }

    /// Builds the frame, with its MIC when `kck` is given.
    pub fn build(
        info: u16,
        replay: u64,
        nonce: &[u8; 32],
        rsc: u64,
        data: &[u8],
        kck: Option<&[u8; 16]>,
    ) -> Vec<u8> {
        let mut f = vec![0u8; KEY_DATA + data.len()];
        f[0] = 2;
        f[1] = 3;
        let body = (f.len() - EAPOL_HEADER) as u16;
        f[2..4].copy_from_slice(&body.to_be_bytes());
        f[4] = 2;
        f[KEY_INFO..KEY_INFO + 2].copy_from_slice(&info.to_be_bytes());
        // key length: 16 for CCMP
        f[7..9].copy_from_slice(&16u16.to_be_bytes());
        f[KEY_REPLAY..KEY_REPLAY + 8].copy_from_slice(&replay.to_be_bytes());
        f[KEY_NONCE..KEY_NONCE + 32].copy_from_slice(nonce);
        f[KEY_RSC..KEY_RSC + 8].copy_from_slice(&rsc.to_le_bytes());
        f[KEY_DATA_LEN..KEY_DATA].copy_from_slice(&(data.len() as u16).to_be_bytes());
        f[KEY_DATA..].copy_from_slice(data);
        if let Some(kck) = kck {
            let mic = eapol_mic(kck, &f);
            f[KEY_MIC..KEY_MIC + 16].copy_from_slice(&mic);
        }
        f
    }
}

/// The MIC of an EAPOL-Key frame of descriptor version 2: HMAC-SHA1-128 of the
/// frame with its MIC field zeroed.
pub fn eapol_mic(kck: &[u8; 16], eapol: &[u8]) -> [u8; 16] {
    let mut f = eapol.to_vec();
    if let Some(mic) = f.get_mut(KEY_MIC..KEY_MIC + 16) {
        mic.fill(0);
    }
    hmac_sha1(kck, &[&f])[..16].try_into().unwrap()
}

fn aes(key: &[u8; 16]) -> Aes128 {
    Aes128::new(GenericArray::from_slice(key))
}

/// AES key wrap (RFC 3394) of `data`, a multiple of 8 bytes, at least 16.
pub fn key_wrap(kek: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let c = aes(kek);
    let n = data.len() / 8;
    let mut a = [0xa6u8; 8];
    let mut r: Vec<[u8; 8]> = data.chunks(8).map(|b| b.try_into().unwrap()).collect();
    for j in 0..6 {
        for (i, ri) in r.iter_mut().enumerate() {
            let mut b = GenericArray::from([0u8; 16]);
            b[..8].copy_from_slice(&a);
            b[8..].copy_from_slice(ri);
            c.encrypt_block(&mut b);
            let t = (n * j + i + 1) as u64;
            a = (u64::from_be_bytes(b[..8].try_into().unwrap()) ^ t).to_be_bytes();
            ri.copy_from_slice(&b[8..]);
        }
    }
    let mut out = a.to_vec();
    r.iter().for_each(|ri| out.extend_from_slice(ri));
    out
}

/// The inverse of [`key_wrap`]; `None` when the integrity check fails.
pub fn key_unwrap(kek: &[u8; 16], wrapped: &[u8]) -> Option<Vec<u8>> {
    if wrapped.len() < 24 || !wrapped.len().is_multiple_of(8) {
        return None;
    }
    let c = aes(kek);
    let n = wrapped.len() / 8 - 1;
    let mut a: [u8; 8] = wrapped[..8].try_into().unwrap();
    let mut r: Vec<[u8; 8]> = wrapped[8..]
        .chunks(8)
        .map(|b| b.try_into().unwrap())
        .collect();
    for j in (0..6).rev() {
        for i in (0..n).rev() {
            let t = (n * j + i + 1) as u64;
            let mut b = GenericArray::from([0u8; 16]);
            b[..8].copy_from_slice(&(u64::from_be_bytes(a) ^ t).to_be_bytes());
            b[8..].copy_from_slice(&r[i]);
            c.decrypt_block(&mut b);
            a = b[..8].try_into().unwrap();
            r[i].copy_from_slice(&b[8..]);
        }
    }
    (a == [0xa6; 8]).then(|| r.concat())
}

/// Length of the MAC header of an MPDU: 24 bytes, plus the fourth address of a
/// frame between two distribution systems, plus the QoS control field.
pub fn header_len(mpdu: &[u8]) -> Option<usize> {
    let f = wlan::Frame::parse(mpdu)?;
    Some(mpdu.len() - f.body.len())
}

/// The PN and key ID of a protected MPDU's CCMP header.
pub fn ccmp_header(mpdu: &[u8]) -> Option<(u64, u8)> {
    let at = header_len(mpdu)?;
    let h = mpdu.get(at..at + CCMP_HEADER)?;
    if h[3] & EXT_IV == 0 {
        return None;
    }
    let pn = u64::from_le_bytes([h[0], h[1], h[4], h[5], h[6], h[7], 0, 0]);
    Some((pn, h[3] >> 6))
}

/// `mpdu` (unprotected) with the Protected bit set and a CCMP header after its
/// MAC header.
pub fn insert_ccmp_header(mpdu: &[u8], pn: u64, key_id: u8) -> Option<Vec<u8>> {
    let at = header_len(mpdu)?;
    let p = pn.to_le_bytes();
    let mut out = Vec::with_capacity(mpdu.len() + CCMP_HEADER + CCMP_MIC);
    out.extend_from_slice(&mpdu[..at]);
    out[1] |= wlan::PROTECTED;
    out.extend_from_slice(&[p[0], p[1], 0, key_id << 6 | EXT_IV, p[2], p[3], p[4], p[5]]);
    out.extend_from_slice(&mpdu[at..]);
    Some(out)
}

/// `mpdu` (opened, CCMP header kept) without its CCMP header and Protected bit.
pub fn strip_ccmp_header(mpdu: &[u8]) -> Option<Vec<u8>> {
    let at = header_len(mpdu)?;
    let mut out = mpdu[..at].to_vec();
    out[1] &= !wlan::PROTECTED;
    out.extend_from_slice(mpdu.get(at + CCMP_HEADER..)?);
    Some(out)
}

/// The additional authenticated data and nonce of a CCMP MPDU whose MAC header
/// is `hdr`.
fn aad_nonce(hdr: &[u8], pn: u64) -> (Vec<u8>, [u8; 13]) {
    let kind = (hdr[0] >> 2) & 3;
    let mut fc = u16::from_le_bytes([hdr[0], hdr[1]]);
    let addr4 = hdr[1] & (wlan::TO_DS | wlan::FROM_DS) == wlan::TO_DS | wlan::FROM_DS;
    let mut priority = 0;
    let mut qos = None;
    if kind == wlan::TYPE_DATA {
        // subtype bits 6:4
        fc &= !0x0070;
        if hdr[0] & 0x80 != 0 {
            // order bit
            fc &= !0x8000;
            let qc = if addr4 { 30 } else { 24 };
            priority = hdr[qc] & 0x0f;
            qos = Some(hdr[qc] & 0x0f);
        }
    } else if kind == wlan::TYPE_MGMT {
        priority = 0x10;
    }
    // retry, power management, more data; protected
    fc = (fc & !0x3800) | 0x4000;
    let mut aad = Vec::with_capacity(30);
    aad.extend_from_slice(&fc.to_le_bytes());
    aad.extend_from_slice(&hdr[4..22]);
    // the sequence number masked, the fragment number kept
    aad.extend_from_slice(&(u16::from_le_bytes([hdr[22], hdr[23]]) & 0x000f).to_le_bytes());
    if addr4 {
        aad.extend_from_slice(&hdr[24..30]);
    }
    if let Some(tid) = qos {
        aad.extend_from_slice(&[tid, 0]);
    }
    let mut nonce = [0u8; 13];
    nonce[0] = priority;
    nonce[1..7].copy_from_slice(&hdr[10..16]);
    nonce[7..].copy_from_slice(&pn.to_be_bytes()[2..]);
    (aad, nonce)
}

/// CCM with an 8-byte MIC and 2-byte length: the MIC of `aad` and `data`, and
/// `data` encrypted (or decrypted) in place.
fn ccm(tk: &[u8; 16], nonce: &[u8; 13], aad: &[u8], data: &mut [u8], encrypt: bool) -> [u8; 8] {
    let c = aes(tk);
    let block = |flags: u8, counter: u16| {
        let mut b = GenericArray::from([0u8; 16]);
        b[0] = flags;
        b[1..14].copy_from_slice(nonce);
        b[14..].copy_from_slice(&counter.to_be_bytes());
        b
    };
    let keystream = |i: u16| {
        let mut s = block(0x01, i);
        c.encrypt_block(&mut s);
        s
    };
    let mut x = block(0x59, data.len() as u16);
    c.encrypt_block(&mut x);
    let mut mac_over = |bytes: &[u8]| {
        for chunk in bytes.chunks(16) {
            chunk.iter().zip(x.iter_mut()).for_each(|(b, x)| *x ^= b);
            c.encrypt_block(&mut x);
        }
    };
    let mut a = (aad.len() as u16).to_be_bytes().to_vec();
    a.extend_from_slice(aad);
    mac_over(&a);
    if !encrypt {
        for (i, chunk) in data.chunks_mut(16).enumerate() {
            let s = keystream(i as u16 + 1);
            chunk.iter_mut().zip(s.iter()).for_each(|(b, s)| *b ^= s);
        }
    }
    mac_over(data);
    if encrypt {
        for (i, chunk) in data.chunks_mut(16).enumerate() {
            let s = keystream(i as u16 + 1);
            chunk.iter_mut().zip(s.iter()).for_each(|(b, s)| *b ^= s);
        }
    }
    let s0 = keystream(0);
    std::array::from_fn(|i| x[i] ^ s0[i])
}

/// Encrypts `mpdu`, which holds its CCMP header and plaintext body, and appends
/// the MIC.
pub fn seal(tk: &[u8; 16], mpdu: &[u8]) -> Option<Vec<u8>> {
    let at = header_len(mpdu)?;
    let (pn, _) = ccmp_header(mpdu)?;
    let (aad, nonce) = aad_nonce(&mpdu[..at], pn);
    let mut out = mpdu.to_vec();
    out[1] |= wlan::PROTECTED;
    let mic = ccm(tk, &nonce, &aad, &mut out[at + CCMP_HEADER..], true);
    out.extend_from_slice(&mic);
    Some(out)
}

/// Checks and decrypts a CCMP-protected MPDU: its header and CCMP header, then
/// the plaintext body, without the MIC. `None` if the MIC does not match.
pub fn open(tk: &[u8; 16], mpdu: &[u8]) -> Option<Vec<u8>> {
    let at = header_len(mpdu)?;
    let (pn, _) = ccmp_header(mpdu)?;
    let end = mpdu.len().checked_sub(CCMP_MIC)?;
    if end < at + CCMP_HEADER {
        return None;
    }
    let (aad, nonce) = aad_nonce(&mpdu[..at], pn);
    let mut out = mpdu[..end].to_vec();
    let mic = ccm(tk, &nonce, &aad, &mut out[at + CCMP_HEADER..], false);
    (mic == mpdu[end..]).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn the_pmk_of_the_ieee_test_vector() {
        assert_eq!(
            pmk("password", b"IEEE").to_vec(),
            hex("f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e")
        );
    }

    #[test]
    fn prf_512_of_the_ieee_test_vector() {
        let mut out = [0u8; 64];
        prf(&[0x0b; 20], b"prefix", b"Hi There", &mut out);
        assert_eq!(
            out.to_vec(),
            hex(concat!(
                "bcd4c650b30b9684951829e0d75f9d54b862175ed9f00606e17d8da35402ffee",
                "75df78c3d31e0f889f012120c0862beb67753e7439ae242edb8373698356cf5a"
            ))
        );
    }

    #[test]
    fn key_wrap_of_rfc_3394() {
        let kek: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let data = hex("00112233445566778899aabbccddeeff");
        let wrapped = key_wrap(&kek, &data);
        assert_eq!(
            wrapped,
            hex("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5")
        );
        assert_eq!(key_unwrap(&kek, &wrapped), Some(data));
        let mut bad = wrapped.clone();
        bad[9] ^= 1;
        assert_eq!(key_unwrap(&kek, &bad), None);
    }

    #[test]
    fn ccmp_of_the_ieee_test_vector() {
        let tk: [u8; 16] = hex("c97c1f67ce371185514a8a19f2bdd52f").try_into().unwrap();
        let mut mpdu = hex("0848c32c0fd2e128a57c5030f1844408abaea5b8fcba8033");
        mpdu.extend(hex("0ce7002076970 3b5".replace(' ', "").as_str()));
        mpdu.extend(hex("f8ba1a55d02f85ae967bb62fb6cda8eb7e78a050"));
        assert_eq!(ccmp_header(&mpdu), Some((0xb503_9776_e70c, 0)));
        let sealed = seal(&tk, &mpdu).unwrap();
        assert_eq!(
            sealed[32..].to_vec(),
            hex("f3d0a2fe9a3dbf2342a643e43246e80c3c04d0197845ce0b16f97623")
        );
        assert_eq!(open(&tk, &sealed), Some(mpdu.clone()));
        let mut bad = sealed.clone();
        bad[40] ^= 1;
        assert_eq!(open(&tk, &bad), None);
    }

    #[test]
    fn ccmp_headers_go_in_and_out() {
        let sta = [2, 0, 0, 0, 0, 1];
        let ap = [2, 0, 0, 0, 0, 2];
        // QoS data, so that the QoS control field goes into the AAD and nonce
        let plain = wlan::Builder::header(wlan::TYPE_DATA, 8, wlan::TO_DS, ap, sta, ap, 5)
            .bytes(&[6, 0])
            .llc(0x0800, &[1, 2, 3])
            .build();
        let with = insert_ccmp_header(&plain, 0x0102_0304_0506, 1).unwrap();
        assert_eq!(ccmp_header(&with), Some((0x0102_0304_0506, 1)));
        let tk = [7u8; 16];
        let sealed = seal(&tk, &with).unwrap();
        assert_eq!(sealed.len(), plain.len() + CCMP_HEADER + CCMP_MIC);
        let opened = open(&tk, &sealed).unwrap();
        assert_eq!(strip_ccmp_header(&opened), Some(plain));
        assert_eq!(open(&[8u8; 16], &sealed), None);
    }

    #[test]
    fn eapol_key_frames_round_trip_with_their_mic() {
        let kck = [3u8; 16];
        let f = EapolKey::build(
            KI_VERSION_AES | KI_PAIRWISE | KI_MIC,
            7,
            &[9; 32],
            0,
            &[0x30, 2, 1, 0],
            Some(&kck),
        );
        let k = EapolKey::parse(&f).unwrap();
        assert_eq!(
            (k.info, k.replay, k.nonce, k.data),
            (0x010a, 7, [9; 32], &[0x30, 2, 1, 0][..])
        );
        assert_eq!(k.mic, eapol_mic(&kck, &f));
        assert_ne!(k.mic, [0; 16]);
    }

    #[test]
    fn the_access_points_rsn_element_is_ccmp_psk() {
        assert!(rsn_is_ccmp_psk(&RSN));
        let mut tkip = RSN;
        tkip[11] = 2;
        assert!(!rsn_is_ccmp_psk(&tkip));
    }
}
