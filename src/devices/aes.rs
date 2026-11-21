//! AES accelerator (0x6003_A000), typical mode: TRIGGER transforms the block of
//! TEXT_IN into TEXT_OUT at once with the key of KEY (MODE 0, 1, 2: encrypt
//! with AES-128, -192, -256; 4, 5, 6: decrypt), and STATE reads idle. The key
//! and blocks are little-endian words of the byte stream. DMA mode
//! (DMA_ENABLE) is not modelled: its trigger does nothing.

use ::aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use ::aes::{Aes128, Aes192, Aes256};

const KEY: u32 = 0x00;
const TEXT_IN: u32 = 0x20;
const TEXT_OUT: u32 = 0x30;
const MODE: u32 = 0x40;
const TRIGGER: u32 = 0x48;
const STATE: u32 = 0x4c;
const DMA_ENABLE: u32 = 0x90;
const DATE: u32 = 0xb4;
const DATE_VALUE: u32 = 0x2019_1210;
const SIZE: usize = 0x100;

pub struct Aes {
    regs: [u32; SIZE / 4],
}

impl Default for Aes {
    fn default() -> Self {
        Self::new()
    }
}

impl Aes {
    pub fn new() -> Self {
        Aes {
            regs: [0; SIZE / 4],
        }
    }

    pub fn reset(&mut self) {
        self.regs = [0; SIZE / 4];
    }

    fn bytes(&self, off: u32, len: usize) -> Vec<u8> {
        (0..len / 4)
            .flat_map(|i| self.regs[(off / 4) as usize + i].to_le_bytes())
            .collect()
    }

    pub fn read(&self, off: u32) -> u32 {
        match off {
            STATE | TRIGGER => 0,
            DATE => DATE_VALUE,
            o if (o as usize) < SIZE => self.regs[(o / 4) as usize],
            _ => 0,
        }
    }

    pub fn write(&mut self, off: u32, v: u32) {
        if off == TRIGGER {
            if v & 1 != 0 && self.regs[(DMA_ENABLE / 4) as usize] & 1 == 0 {
                self.transform();
            }
            return;
        }
        if let Some(r) = self.regs.get_mut((off / 4) as usize) {
            *r = v;
        }
    }

    fn transform(&mut self) {
        let mode = self.regs[(MODE / 4) as usize] & 7;
        let mut block = GenericArray::clone_from_slice(&self.bytes(TEXT_IN, 16));
        let decrypt = mode & 4 != 0;
        macro_rules! run {
            ($cipher:ty, $len:expr) => {{
                let c = <$cipher>::new(GenericArray::from_slice(&self.bytes(KEY, $len)));
                if decrypt {
                    c.decrypt_block(&mut block)
                } else {
                    c.encrypt_block(&mut block)
                }
            }};
        }
        match mode & 3 {
            0 => run!(Aes128, 16),
            1 => run!(Aes192, 24),
            2 => run!(Aes256, 32),
            _ => return,
        }
        for (i, w) in block.chunks(4).enumerate() {
            self.regs[(TEXT_OUT / 4) as usize + i] = u32::from_le_bytes(w.try_into().unwrap());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(hex: &str) -> Vec<u32> {
        (0..hex.len())
            .step_by(8)
            .map(|i| {
                let b: Vec<u8> = (0..4)
                    .map(|k| u8::from_str_radix(&hex[i + 2 * k..i + 2 * k + 2], 16).unwrap())
                    .collect();
                u32::from_le_bytes(b.try_into().unwrap())
            })
            .collect()
    }

    /// Runs one block, as the driver does: key, mode, input, trigger, then the
    /// output once STATE reads idle.
    fn block(aes: &mut Aes, mode: u32, key: &str, input: &str) -> Vec<u32> {
        for (i, w) in words(key).into_iter().enumerate() {
            aes.write(KEY + 4 * i as u32, w);
        }
        aes.write(MODE, mode);
        for (i, w) in words(input).into_iter().enumerate() {
            aes.write(TEXT_IN + 4 * i as u32, w);
        }
        aes.write(TRIGGER, 1);
        assert_eq!(aes.read(STATE), 0);
        (0..4).map(|i| aes.read(TEXT_OUT + 4 * i)).collect()
    }

    #[test]
    fn the_fips_197_blocks() {
        let mut aes = Aes::new();
        let k128 = "000102030405060708090a0b0c0d0e0f";
        let k256 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let plain = "00112233445566778899aabbccddeeff";
        let c128 = "69c4e0d86a7b0430d8cdb78070b4c55a";
        let c256 = "8ea2b7ca516745bfeafc49904b496089";
        assert_eq!(block(&mut aes, 0, k128, plain), words(c128));
        assert_eq!(block(&mut aes, 4, k128, c128), words(plain));
        assert_eq!(block(&mut aes, 2, k256, plain), words(c256));
        assert_eq!(block(&mut aes, 6, k256, c256), words(plain));
    }
}
