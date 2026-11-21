//! An access point, open or WPA2-Personal: beacons, probe responses, open
//! authentication, association, the 4-way handshake, and data frames bridged to
//! Ethernet frames (CCMP-protected under WPA2: pairwise key 0, group key 1).

use std::collections::{BTreeMap, VecDeque};

use super::ieee80211::{self as wlan, BROADCAST, Builder, Frame, Mac};
use super::wpa::{self, EapolKey, Ptk};
use crate::machine::TICK_HZ;

/// Beacon interval: 100 TU.
const BEACON_TU: u16 = 100;
const BEACON_PERIOD: u64 = TICK_HZ * 1024 * BEACON_TU as u64 / 1_000_000;
/// Capabilities: ESS, short slot time; privacy under WPA2.
const CAPABILITIES: u16 = 0x0401;
const PRIVACY: u16 = 0x0010;

/// Each message of the 4-way handshake is sent this many times, this far apart,
/// before the station is sent away.
const HANDSHAKE_TRIES: u8 = 4;
const HANDSHAKE_RETRY: u64 = TICK_HZ;
/// Status code: invalid information element (no or another RSN element).
const STATUS_INVALID_IE: u16 = 40;
/// Reason codes: class 3 frame from a station not associated; 4-way handshake
/// timeout.
const REASON_NOT_ASSOCIATED: u16 = 7;
const REASON_HANDSHAKE_TIMEOUT: u16 = 15;
/// Key ID of the group key.
const GTK_ID: u8 = 1;

/// The keys of a WPA2-Personal access point.
struct Wpa {
    pmk: [u8; 32],
    gtk: [u8; 16],
    /// PN of the last group frame sent.
    gtk_pn: u64,
    /// Feeds the nonces.
    counter: u64,
}

enum Keys {
    /// Message 1 (no PTK yet) or 3 was sent; `tries` times so far.
    Handshake {
        anonce: [u8; 32],
        replay: u64,
        ptk: Option<Ptk>,
        tries: u8,
        deadline: u64,
        /// A wrong MIC was reported for this handshake.
        mic_reported: bool,
    },
    Installed {
        ptk: Ptk,
        /// PN of the last frame sent, and of the last received.
        tx_pn: u64,
        rx_pn: Option<u64>,
    },
}

struct Station {
    associated: bool,
    aid: u16,
    /// The RSN element body of the association request.
    rsn: Vec<u8>,
    keys: Option<Keys>,
}

pub struct AccessPoint {
    pub ssid: String,
    pub bssid: Mac,
    pub channel: u8,
    seq: u16,
    wpa: Option<Wpa>,
    stations: BTreeMap<Mac, Station>,
    next_beacon: u64,
    /// 802.11 frames for the chip.
    pub out: VecDeque<Vec<u8>>,
    /// Ethernet frames from the stations.
    pub to_lan: VecDeque<Vec<u8>>,
    /// What happened, for the log.
    pub events: VecDeque<String>,
}

impl AccessPoint {
    /// An open access point, or a WPA2-Personal one with `passphrase`.
    pub fn new(ssid: &str, bssid: Mac, channel: u8, passphrase: Option<&str>) -> Self {
        let wpa = passphrase.map(|p| {
            let mut gtk = [0u8; 16];
            wpa::prf(&bssid, b"Group key expansion", ssid.as_bytes(), &mut gtk);
            Wpa {
                pmk: wpa::pmk(p, ssid.as_bytes()),
                gtk,
                gtk_pn: 0,
                counter: 0,
            }
        });
        AccessPoint {
            ssid: ssid.into(),
            bssid,
            channel,
            seq: 0,
            wpa,
            stations: BTreeMap::new(),
            next_beacon: 0,
            out: VecDeque::new(),
            to_lan: VecDeque::new(),
            events: VecDeque::new(),
        }
    }

    fn seq(&mut self) -> u16 {
        self.seq = (self.seq + 1) & 0xfff;
        self.seq
    }

    fn capabilities(&self) -> u16 {
        if self.wpa.is_some() {
            CAPABILITIES | PRIVACY
        } else {
            CAPABILITIES
        }
    }

    /// The fixed fields and elements of beacons and probe responses.
    fn bss_body(&self, b: Builder, now: u64, beacon: bool) -> Builder {
        let mut b = b
            .u64(now / (TICK_HZ / 1_000_000))
            .u16(BEACON_TU)
            .u16(self.capabilities())
            .element(wlan::IE_SSID, self.ssid.as_bytes())
            .element(wlan::IE_RATES, &wlan::RATES)
            .element(wlan::IE_DS, &[self.channel]);
        if beacon {
            // DTIM count 0, period 1, no traffic buffered
            b = b.element(wlan::IE_TIM, &[0, 1, 0, 0]);
        }
        if self.wpa.is_some() {
            b = b.element(wlan::IE_RSN, &wpa::RSN);
        }
        b.element(wlan::IE_EXT_RATES, &wlan::EXT_RATES)
    }

    /// Time of the next beacon or handshake retry.
    pub fn next_event(&self) -> u64 {
        self.stations
            .values()
            .filter_map(|s| match s.keys {
                Some(Keys::Handshake { deadline, .. }) => Some(deadline),
                _ => None,
            })
            .fold(self.next_beacon, u64::min)
    }

    /// Sends the beacons due by `now`, and retries or ends the handshakes whose
    /// message went unanswered.
    pub fn poll(&mut self, now: u64) {
        if now >= self.next_beacon {
            let seq = self.seq();
            let b = Builder::mgmt(wlan::BEACON, BROADCAST, self.bssid, self.bssid, seq);
            let f = self.bss_body(b, now, true).build();
            self.out.push_back(f);
            self.next_beacon = now - now % BEACON_PERIOD + BEACON_PERIOD;
        }
        let due: Vec<Mac> = self
            .stations
            .iter()
            .filter(|(_, s)| matches!(s.keys, Some(Keys::Handshake { deadline, .. }) if deadline <= now))
            .map(|(&m, _)| m)
            .collect();
        for sta in due {
            let Some(Keys::Handshake { tries, .. }) = self.stations[&sta].keys else {
                continue;
            };
            if tries < HANDSHAKE_TRIES {
                self.send_handshake(sta, now);
            } else {
                self.stations.remove(&sta);
                self.deauth(sta, REASON_HANDSHAKE_TIMEOUT);
                self.events.push_back(format!(
                    "station {} sent away: no valid answer to the 4-way handshake (wrong passphrase?)",
                    wlan::fmt_mac(&sta)
                ));
            }
        }
    }

    /// The station `mac` is associated, and has its keys under WPA2.
    pub fn associated(&self, mac: &Mac) -> bool {
        self.stations.get(mac).is_some_and(|s| {
            s.associated && (self.wpa.is_none() || matches!(s.keys, Some(Keys::Installed { .. })))
        })
    }

    /// A frame the chip sent.
    pub fn receive(&mut self, frame: &[u8], now: u64) {
        let Some(f) = Frame::parse(frame) else {
            return;
        };
        if f.is_mgmt(wlan::PROBE_REQ) {
            let ssid = wlan::element(f.body, wlan::IE_SSID).unwrap_or(&[]);
            if ssid.is_empty() || ssid == self.ssid.as_bytes() {
                let seq = self.seq();
                let b = Builder::mgmt(wlan::PROBE_RESP, f.addr2, self.bssid, self.bssid, seq);
                let resp = self.bss_body(b, now, false).build();
                self.out.push_back(resp);
            }
            return;
        }
        if f.addr1 != self.bssid {
            return;
        }
        let sta = f.addr2;
        if f.kind == wlan::TYPE_MGMT {
            match f.subtype {
                wlan::AUTH => {
                    let algorithm = u16::from_le_bytes([f.body[0], f.body[1]]);
                    // open system only
                    let status = if algorithm == 0 { 0 } else { 13 };
                    let seq = self.seq();
                    let resp = Builder::mgmt(wlan::AUTH, sta, self.bssid, self.bssid, seq)
                        .u16(algorithm)
                        .u16(2)
                        .u16(status)
                        .build();
                    self.out.push_back(resp);
                    if status == 0 {
                        let aid = self.stations.len() as u16 + 1;
                        self.stations.entry(sta).or_insert(Station {
                            associated: false,
                            aid,
                            rsn: Vec::new(),
                            keys: None,
                        });
                    }
                }
                wlan::ASSOC_REQ | wlan::REASSOC_REQ => self.associate(&f, now),
                wlan::DEAUTH | wlan::DISASSOC if self.stations.remove(&sta).is_some() => {
                    self.events
                        .push_back(format!("station {} left", wlan::fmt_mac(&sta)));
                }
                _ => {}
            }
            return;
        }
        if f.kind != wlan::TYPE_DATA || f.flags & wlan::TO_DS == 0 {
            return;
        }
        if !self.stations.get(&sta).is_some_and(|s| s.associated) {
            // class 3 frame from a station that is not associated
            self.deauth(sta, REASON_NOT_ASSOCIATED);
            return;
        }
        if f.is_null() {
            return;
        }
        let plain;
        let body = if f.flags & wlan::PROTECTED != 0 {
            let Some(p) = self.decrypt(&sta, frame) else {
                return;
            };
            plain = p;
            match Frame::parse(&plain) {
                Some(p) => p.body,
                None => return,
            }
        } else {
            f.body
        };
        let Some((ethertype, payload)) = wlan::llc(body) else {
            return;
        };
        if ethertype == wpa::ETHERTYPE_EAPOL && self.wpa.is_some() {
            self.eapol(sta, payload, now);
        } else if self.associated(&sta) && (self.wpa.is_none() || f.flags & wlan::PROTECTED != 0) {
            self.to_lan
                .push_back(wlan::ethernet(f.addr3, sta, ethertype, payload));
        }
    }

    /// An association request: accepted for the right SSID and, under WPA2, an
    /// RSN element with CCMP and PSK, which starts the 4-way handshake.
    fn associate(&mut self, f: &Frame, now: u64) {
        let sta = f.addr2;
        let ies = if f.subtype == wlan::ASSOC_REQ {
            f.body.get(4..)
        } else {
            f.body.get(10..)
        };
        let ssid = ies.and_then(|i| wlan::element(i, wlan::IE_SSID));
        let rsn = ies.and_then(|i| wlan::element(i, wlan::IE_RSN));
        let wpa = self.wpa.is_some();
        let Some(station) = self.stations.get_mut(&sta) else {
            self.deauth(sta, REASON_NOT_ASSOCIATED);
            return;
        };
        let rsn_ok = !wpa || rsn.is_some_and(wpa::rsn_is_ccmp_psk);
        let status = match (ssid == Some(self.ssid.as_bytes()), rsn_ok) {
            (true, true) => 0,
            (true, false) => STATUS_INVALID_IE,
            (false, _) => 1,
        };
        station.associated = status == 0;
        station.rsn = rsn.unwrap_or_default().to_vec();
        station.keys = None;
        let aid = station.aid;
        let subtype = if f.subtype == wlan::ASSOC_REQ {
            wlan::ASSOC_RESP
        } else {
            wlan::REASSOC_RESP
        };
        let seq = self.seq();
        let resp = Builder::mgmt(subtype, sta, self.bssid, self.bssid, seq)
            .u16(self.capabilities())
            .u16(status)
            .u16(0xc000 | aid)
            .element(wlan::IE_RATES, &wlan::RATES)
            .element(wlan::IE_EXT_RATES, &wlan::EXT_RATES)
            .build();
        self.out.push_back(resp);
        if status == STATUS_INVALID_IE {
            self.events.push_back(format!(
                "station {} refused: {} needs WPA2-Personal (CCMP, PSK) and its passphrase",
                wlan::fmt_mac(&sta),
                self.ssid
            ));
        }
        if status != 0 {
            return;
        }
        self.events.push_back(format!(
            "station {} associated with {}",
            wlan::fmt_mac(&sta),
            self.ssid
        ));
        if let Some(w) = &mut self.wpa {
            w.counter += 1;
            let mut anonce = [0u8; 32];
            let seed = [&sta[..], &w.counter.to_le_bytes()].concat();
            wpa::prf(&self.bssid, b"Init Counter", &seed, &mut anonce);
            self.stations.get_mut(&sta).unwrap().keys = Some(Keys::Handshake {
                anonce,
                replay: 0,
                ptk: None,
                tries: 0,
                deadline: now,
                mic_reported: false,
            });
            self.send_handshake(sta, now);
        }
    }

    /// Sends message 1 (no PTK yet) or 3 of the handshake to `sta`, with a new
    /// replay counter.
    fn send_handshake(&mut self, sta: Mac, now: u64) {
        let (Some(w), Some(station)) = (&self.wpa, self.stations.get_mut(&sta)) else {
            return;
        };
        let Some(Keys::Handshake {
            anonce,
            replay,
            ptk,
            tries,
            deadline,
            ..
        }) = &mut station.keys
        else {
            return;
        };
        *replay += 1;
        *tries += 1;
        *deadline = now + HANDSHAKE_RETRY;
        let eapol = match ptk {
            None => EapolKey::build(
                wpa::KI_VERSION_AES | wpa::KI_PAIRWISE | wpa::KI_ACK,
                *replay,
                anonce,
                0,
                &[],
                None,
            ),
            Some(ptk) => {
                // our RSN element and the group key, padded and wrapped
                let mut data = vec![wlan::IE_RSN, wpa::RSN.len() as u8];
                data.extend_from_slice(&wpa::RSN);
                data.extend_from_slice(&[0xdd, 22, 0x00, 0x0f, 0xac, 0x01, GTK_ID, 0]);
                data.extend_from_slice(&w.gtk);
                if !data.len().is_multiple_of(8) {
                    data.push(0xdd);
                    data.resize(data.len().next_multiple_of(8), 0);
                }
                EapolKey::build(
                    wpa::KI_VERSION_AES
                        | wpa::KI_PAIRWISE
                        | wpa::KI_INSTALL
                        | wpa::KI_ACK
                        | wpa::KI_MIC
                        | wpa::KI_SECURE
                        | wpa::KI_ENCRYPTED,
                    *replay,
                    anonce,
                    w.gtk_pn + 1,
                    &wpa::key_wrap(&ptk.kek, &data),
                    Some(&ptk.kck),
                )
            }
        };
        let seq = self.seq();
        let f = Builder::header(
            wlan::TYPE_DATA,
            0,
            wlan::FROM_DS,
            sta,
            self.bssid,
            self.bssid,
            seq,
        )
        .llc(wpa::ETHERTYPE_EAPOL, &eapol)
        .build();
        self.out.push_back(f);
    }

    /// An EAPOL frame from `sta`: message 2 or 4 of the handshake.
    fn eapol(&mut self, sta: Mac, eapol: &[u8], now: u64) {
        let (Some(w), Some(station)) = (&self.wpa, self.stations.get_mut(&sta)) else {
            return;
        };
        let Some(key) = EapolKey::parse(eapol) else {
            return;
        };
        let Some(Keys::Handshake {
            anonce,
            replay,
            ptk,
            mic_reported,
            ..
        }) = &mut station.keys
        else {
            return;
        };
        if key.info & wpa::KI_MIC == 0 || key.info & wpa::KI_ACK != 0 || key.replay != *replay {
            return;
        }
        match ptk {
            None => {
                let derived = Ptk::derive(&w.pmk, &self.bssid, &sta, anonce, &key.nonce);
                if wpa::eapol_mic(&derived.kck, eapol) != key.mic {
                    if !*mic_reported {
                        *mic_reported = true;
                        self.events.push_back(format!(
                            "station {}: the MIC of its handshake message does not match (wrong passphrase?)",
                            wlan::fmt_mac(&sta)
                        ));
                    }
                    return;
                }
                if wlan::element(key.data, wlan::IE_RSN) != Some(&station.rsn[..]) {
                    self.events.push_back(format!(
                        "WARN station {}: its handshake RSN element differs from its association's",
                        wlan::fmt_mac(&sta)
                    ));
                }
                *ptk = Some(derived);
                self.send_handshake(sta, now);
            }
            Some(p) => {
                if key.info & wpa::KI_SECURE == 0 || wpa::eapol_mic(&p.kck, eapol) != key.mic {
                    return;
                }
                station.keys = Some(Keys::Installed {
                    ptk: p.clone(),
                    tx_pn: 0,
                    rx_pn: None,
                });
                self.events.push_back(format!(
                    "station {} joined {} with WPA2",
                    wlan::fmt_mac(&sta),
                    self.ssid
                ));
            }
        }
    }

    /// The plaintext MPDU (CCMP header removed) of a protected frame from `sta`,
    /// if its MIC is right and it is not a replay.
    fn decrypt(&mut self, sta: &Mac, frame: &[u8]) -> Option<Vec<u8>> {
        let Some(Keys::Installed { ptk, rx_pn, .. }) = &mut self.stations.get_mut(sta)?.keys else {
            return None;
        };
        let (pn, _) = wpa::ccmp_header(frame)?;
        if rx_pn.is_some_and(|last| pn <= last) {
            return None;
        }
        let opened = wpa::open(&ptk.tk, frame)?;
        *rx_pn = Some(pn);
        wpa::strip_ccmp_header(&opened)
    }

    fn deauth(&mut self, sta: Mac, reason: u16) {
        let seq = self.seq();
        let f = Builder::mgmt(wlan::DEAUTH, sta, self.bssid, self.bssid, seq)
            .u16(reason)
            .build();
        self.out.push_back(f);
    }

    /// An Ethernet frame for the stations.
    pub fn send(&mut self, eth: &[u8]) {
        let Some((dst, src, ethertype, payload)) = wlan::parse_ethernet(eth) else {
            return;
        };
        let group = dst[0] & 1 != 0;
        if !group && !self.associated(&dst) {
            return;
        }
        if group && !self.stations.keys().any(|m| self.associated(m)) {
            return;
        }
        let seq = self.seq();
        let f = Builder::header(wlan::TYPE_DATA, 0, wlan::FROM_DS, dst, self.bssid, src, seq)
            .llc(ethertype, payload)
            .build();
        let (tk, pn, key_id) = match (&mut self.wpa, group) {
            (None, _) => {
                self.out.push_back(f);
                return;
            }
            (Some(w), true) => {
                w.gtk_pn += 1;
                (w.gtk, w.gtk_pn, GTK_ID)
            }
            (Some(_), false) => {
                let Some(Keys::Installed { ptk, tx_pn, .. }) =
                    &mut self.stations.get_mut(&dst).unwrap().keys
                else {
                    return;
                };
                *tx_pn += 1;
                (ptk.tk, *tx_pn, 0)
            }
        };
        if let Some(sealed) =
            wpa::insert_ccmp_header(&f, pn, key_id).and_then(|m| wpa::seal(&tk, &m))
        {
            self.out.push_back(sealed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BSSID: Mac = [0x02, 0xe5, 0, 0, 0, 1];
    const STA: Mac = [0x7c, 0xdf, 0xa1, 1, 2, 3];

    fn reply(ap: &mut AccessPoint) -> Vec<u8> {
        ap.out.pop_front().expect("a reply")
    }

    fn auth(ap: &mut AccessPoint) {
        let auth = Builder::mgmt(wlan::AUTH, BSSID, STA, BSSID, 3)
            .u16(0)
            .u16(1)
            .u16(0)
            .build();
        ap.receive(&auth, 0);
        let r = reply(ap);
        assert_eq!(&Frame::parse(&r).unwrap().body[..6], &[0, 0, 2, 0, 0, 0]);
    }

    fn assoc(ap: &mut AccessPoint, rsn: Option<&[u8]>) -> u16 {
        let mut b = Builder::mgmt(wlan::ASSOC_REQ, BSSID, STA, BSSID, 4)
            .u16(0x0411)
            .u16(10)
            .element(wlan::IE_SSID, b"emu");
        if let Some(rsn) = rsn {
            b = b.element(wlan::IE_RSN, rsn);
        }
        ap.receive(&b.build(), 0);
        let r = reply(ap);
        let r = Frame::parse(&r).unwrap();
        assert!(r.is_mgmt(wlan::ASSOC_RESP));
        u16::from_le_bytes([r.body[2], r.body[3]])
    }

    /// The EAPOL PDU of a data frame from the access point.
    fn eapol_of(frame: &[u8]) -> Vec<u8> {
        let f = Frame::parse(frame).unwrap();
        assert_eq!(f.flags & wlan::PROTECTED, 0);
        let (t, p) = wlan::llc(f.body).unwrap();
        assert_eq!(t, wpa::ETHERTYPE_EAPOL);
        p.to_vec()
    }

    fn to_ap(da: Mac, payload_type: u16, payload: &[u8], seq: u16) -> Vec<u8> {
        Builder::header(wlan::TYPE_DATA, 0, wlan::TO_DS, BSSID, STA, da, seq)
            .llc(payload_type, payload)
            .build()
    }

    #[test]
    fn a_station_scans_authenticates_associates_and_sends_data() {
        let mut ap = AccessPoint::new("emu", BSSID, 1, None);
        ap.poll(0);
        let beacon = reply(&mut ap);
        let b = Frame::parse(&beacon).unwrap();
        assert!(b.is_mgmt(wlan::BEACON));
        assert_eq!(
            wlan::element(&b.body[12..], wlan::IE_SSID),
            Some(&b"emu"[..])
        );
        assert_eq!(wlan::element(&b.body[12..], wlan::IE_RSN), None);
        assert_eq!(ap.next_event(), BEACON_PERIOD);

        let probe = Builder::mgmt(wlan::PROBE_REQ, BROADCAST, STA, BROADCAST, 1)
            .element(wlan::IE_SSID, b"")
            .build();
        ap.receive(&probe, 0);
        let r = reply(&mut ap);
        let r = Frame::parse(&r).unwrap();
        assert!(r.is_mgmt(wlan::PROBE_RESP));
        assert_eq!(r.addr1, STA);

        // data before association: deauthenticated
        let data = to_ap(BROADCAST, 0x0806, &[0; 28], 2);
        ap.receive(&data, 0);
        assert!(Frame::parse(&reply(&mut ap)).unwrap().is_mgmt(wlan::DEAUTH));

        auth(&mut ap);
        assert_eq!(assoc(&mut ap, None), 0);
        assert!(ap.associated(&STA));

        ap.receive(&data, 0);
        let eth = ap.to_lan.pop_front().unwrap();
        assert_eq!(
            wlan::parse_ethernet(&eth).unwrap(),
            (BROADCAST, STA, 0x0806, &[0u8; 28][..])
        );

        ap.send(&wlan::ethernet(STA, [2, 0, 0, 0, 0, 9], 0x0800, &[1, 2]));
        let r = reply(&mut ap);
        let r = Frame::parse(&r).unwrap();
        assert_eq!(
            (r.addr1, r.addr2, r.addr3),
            (STA, BSSID, [2, 0, 0, 0, 0, 9])
        );
        assert_eq!(r.flags, wlan::FROM_DS);
        assert_eq!(wlan::llc(r.body), Some((0x0800, &[1u8, 2][..])));
    }

    /// Runs the station side of the handshake with `passphrase`: returns the PTK
    /// and GTK it installs.
    fn handshake(ap: &mut AccessPoint, passphrase: &str) -> Option<(Ptk, [u8; 16])> {
        let msg1 = eapol_of(&reply(ap));
        let k1 = EapolKey::parse(&msg1).unwrap();
        assert_eq!(
            k1.info,
            wpa::KI_VERSION_AES | wpa::KI_PAIRWISE | wpa::KI_ACK
        );
        let snonce = [0x5a; 32];
        let pmk = wpa::pmk(passphrase, b"emu");
        let ptk = Ptk::derive(&pmk, &BSSID, &STA, &k1.nonce, &snonce);
        let rsn_ie = [&[wlan::IE_RSN, 20][..], &wpa::RSN].concat();
        let msg2 = EapolKey::build(
            wpa::KI_VERSION_AES | wpa::KI_PAIRWISE | wpa::KI_MIC,
            k1.replay,
            &snonce,
            0,
            &rsn_ie,
            Some(&ptk.kck),
        );
        ap.receive(&to_ap(BSSID, wpa::ETHERTYPE_EAPOL, &msg2, 5), 0);
        let msg3 = eapol_of(&ap.out.pop_front()?);
        let k3 = EapolKey::parse(&msg3).unwrap();
        assert_eq!(k3.info, 0x13ca);
        assert_eq!(k3.replay, k1.replay + 1);
        assert_eq!(k3.nonce, k1.nonce);
        assert_eq!(k3.mic, wpa::eapol_mic(&ptk.kck, &msg3));
        let data = wpa::key_unwrap(&ptk.kek, k3.data).unwrap();
        assert_eq!(wlan::element(&data, wlan::IE_RSN), Some(&wpa::RSN[..]));
        let kde = wlan::element(&data, 0xdd).unwrap();
        assert_eq!(&kde[..6], &[0x00, 0x0f, 0xac, 0x01, GTK_ID, 0]);
        let gtk: [u8; 16] = kde[6..].try_into().unwrap();
        let msg4 = EapolKey::build(
            wpa::KI_VERSION_AES | wpa::KI_PAIRWISE | wpa::KI_MIC | wpa::KI_SECURE,
            k3.replay,
            &[0; 32],
            0,
            &[],
            Some(&ptk.kck),
        );
        ap.receive(&to_ap(BSSID, wpa::ETHERTYPE_EAPOL, &msg4, 6), 0);
        Some((ptk, gtk))
    }

    #[test]
    fn a_wpa2_station_runs_the_handshake_then_exchanges_ccmp_frames() {
        let mut ap = AccessPoint::new("emu", BSSID, 1, Some("passphrase"));
        ap.poll(0);
        let beacon = reply(&mut ap);
        let b = Frame::parse(&beacon).unwrap();
        assert_eq!(
            wlan::element(&b.body[12..], wlan::IE_RSN),
            Some(&wpa::RSN[..])
        );
        assert_ne!(u16::from_le_bytes([b.body[10], b.body[11]]) & PRIVACY, 0);

        auth(&mut ap);
        // no RSN element: refused
        assert_eq!(assoc(&mut ap, None), STATUS_INVALID_IE);
        assert!(ap.events.iter().any(|e| e.contains("needs WPA2")));
        assert_eq!(assoc(&mut ap, Some(&wpa::RSN)), 0);
        assert!(!ap.associated(&STA), "no keys yet");
        let (ptk, gtk) = handshake(&mut ap, "passphrase").unwrap();
        assert!(ap.associated(&STA));
        assert!(ap.events.iter().any(|e| e.contains("joined emu with WPA2")));

        // plaintext data is dropped, protected data goes through
        let data = to_ap(BSSID, 0x0806, &[0; 28], 7);
        ap.receive(&data, 0);
        assert!(ap.to_lan.is_empty());
        let sealed = wpa::insert_ccmp_header(&data, 1, 0)
            .and_then(|m| wpa::seal(&ptk.tk, &m))
            .unwrap();
        ap.receive(&sealed, 0);
        assert_eq!(
            wlan::parse_ethernet(&ap.to_lan.pop_front().unwrap()).unwrap(),
            (BSSID, STA, 0x0806, &[0u8; 28][..])
        );
        // a replay is dropped
        ap.receive(&sealed, 0);
        assert!(ap.to_lan.is_empty());

        // unicast under the PTK, group frames under the GTK
        ap.send(&wlan::ethernet(STA, [2, 0, 0, 0, 0, 9], 0x0800, &[1, 2]));
        let r = reply(&mut ap);
        assert_eq!(wpa::ccmp_header(&r), Some((1, 0)));
        let opened = wpa::strip_ccmp_header(&wpa::open(&ptk.tk, &r).unwrap()).unwrap();
        let o = Frame::parse(&opened).unwrap();
        assert_eq!(wlan::llc(o.body), Some((0x0800, &[1u8, 2][..])));
        ap.send(&wlan::ethernet(BROADCAST, [2, 0, 0, 0, 0, 9], 0x0806, &[3]));
        let r = reply(&mut ap);
        assert_eq!(wpa::ccmp_header(&r), Some((1, GTK_ID)));
        assert!(wpa::open(&gtk, &r).is_some());
    }

    #[test]
    fn a_wrong_passphrase_ends_in_a_handshake_timeout() {
        let mut ap = AccessPoint::new("emu", BSSID, 1, Some("passphrase"));
        ap.poll(0);
        ap.out.clear();
        auth(&mut ap);
        assert_eq!(assoc(&mut ap, Some(&wpa::RSN)), 0);
        assert!(handshake(&mut ap, "wrong passphrase").is_none());
        assert!(ap.events.iter().any(|e| e.contains("MIC")));
        // message 1 again each second, then the station is sent away
        let next = |ap: &mut AccessPoint| loop {
            let t = ap.next_event();
            ap.poll(t);
            ap.out
                .retain(|f| !Frame::parse(f).unwrap().is_mgmt(wlan::BEACON));
            if let Some(f) = ap.out.pop_front() {
                return (t, f);
            }
        };
        for _ in 1..HANDSHAKE_TRIES {
            let (t, f) = next(&mut ap);
            assert!(t.is_multiple_of(HANDSHAKE_RETRY));
            let msg = eapol_of(&f);
            assert_eq!(EapolKey::parse(&msg).unwrap().info & wpa::KI_MIC, 0);
        }
        let (_, r) = next(&mut ap);
        let r = Frame::parse(&r).unwrap();
        assert!(r.is_mgmt(wlan::DEAUTH));
        assert_eq!(r.body, &REASON_HANDSHAKE_TIMEOUT.to_le_bytes());
        assert!(!ap.associated(&STA));
    }
}
