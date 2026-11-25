# esp32s3-rax

An ESP32-S3 emulator: the PRO_CPU is [rax](https://github.com/Georges760/rax/tree/feat/xtensa-esp32s3)'s
Xtensa LX7 interpreter (`rax::isa::xtensa`, with the ESP32-S3 core configuration), and this crate
models the rest of the chip: the memory map, the boot from the internal ROM, and the peripherals.
The board around the chip talks to it through the peripherals, and the chip's Wi-Fi to an emulated
network. [bitaxe-emu-rs](https://github.com/bitaxeorg/bitaxe-emu-rs) builds the Bitaxe boards on it.

## Building

rax is not on crates.io yet, so this crate takes it by path from `../../upstream/rax`: a checkout of
its `feat/xtensa-esp32s3` branch in an `upstream` directory beside the `emulator` directory holding this crate. Its repository is large (its
documents take about 2.7 GB); cargo reads only `Cargo.toml`, `Cargo.lock`, `LICENSE`, `LICENSES`,
`THIRD_PARTY_NOTICES.md`, `src`, `capi` and `vendor/vm-memory`:

```bash
git clone --filter=blob:none --no-checkout -b feat/xtensa-esp32s3 \
  https://github.com/Georges760/rax ../../upstream/rax
cd ../../upstream/rax
git sparse-checkout set --no-cone /Cargo.toml /Cargo.lock /LICENSE /LICENSES \
  /THIRD_PARTY_NOTICES.md /src /capi /vendor/vm-memory
git checkout feat/xtensa-esp32s3
```

## Running an image

```bash
cargo run --release --bin esp32s3-run -- \
  --rom esp32s3_rev0_rom.bin --flash <merged image> [--elf <app ELF>]
```

It prints the console (UART0 and USB-Serial-JTAG) on stdout and writes the RTT up-buffer 0 to a
file, then reports the exceptions, the unmodelled registers touched and, with `--profile`, the
opcodes executed. `ESP32S3_I2C_TRACE=1` traces the I2C command lists. The ROM image is not
included: it ships with Espressif's QEMU ([espressif/qemu](https://github.com/espressif/qemu),
`pc-bios/esp32s3_rev0_rom.bin`). `--rom` defaults to the path in `ESP32S3_ROM` at build time
(bitaxe-emu-rs's Nix package fetches the image and sets it), else to
`../../upstream/qemu-espressif/pc-bios/esp32s3_rev0_rom.bin` from this crate's directory.

## Embedding

A host reaches the board side through `Esp32s3::periph()`: UART bytes (`uart[n].tx_out`,
`receive`), I2C devices (`i2c[n].attach`, the `I2cDevice` trait), GPIO levels (`gpio.set_input`,
`gpio.output`), ADC1 inputs (`sens.set_adc1_mv(channel, mv)`) and the LCD transfers
(`lcd_cam.out`, a queue of `LcdWrite { cmd, data }` to drain). The Wi-Fi MAC exchanges whole
802.11 frames with `Soc::air`, an `net::Air`; `net::Network` is an access point (open, or
WPA2-Personal) with a router behind it, a client of the chip's own access point and host ports forwarded to the chip.

## Status (2026-11-21)

Claim classes as in rax's documentation policy.

| Part | Where | Claim |
|---|---|---|
| ESP32-S3 machine: ROM, SRAM with its I-bus and D-bus views, RTC memories, flash and octal PSRAM windows through the cache MMU (PSRAM pages readable, writable and executable), instruction-count time, WAITI fast-forward, function stubs; APP_CPU (PRID 0xABAB) released by SYSTEM_CORE_1_CONTROL_0 (clock on, not stalled, out of reset; setting CORE_1_RESETING restarts it), both cores running each time slice in turn, each with its interrupt lines from the matrix, peripheral accesses never earlier than the latest one (the second core of a slice starts from the slice start) | `src/machine/` | **Implemented** |
| Devices: SYSTEM and clocks, RTC_CNTL (reset causes, software resets, RTC time), interrupt matrix, UART0-2 (baud-paced, thresholds, RX timeout), USB-Serial-JTAG (serial side, with a host whose start-of-frame packets keep SOF_INT_RAW set), TIMG0/1 (timers, MWDT interrupt stages, RTC calibration), SYSTIMER, eFuse (MAC and ADC calibration version 1), SPI1 + SPI NOR flash on CS0 + octal PSRAM on CS1 (mode registers, register and memory commands), EXTMEM + MMU, SHA (register mode), GPIO + IO_MUX (levels, interrupts, strapping), I2C0/1 master with an `I2cDevice` trait for board devices, RNG; the Bluetooth controller answers its initialisation (version 0x0900_1b00 at 0x6003_1004, the bit-31 requests of 0x000 and 0x01c complete at once) without a link layer; read-back register files for SPI0, LEDC, RMT, PMS and other configuration-only blocks; the analog (`regi2c`, APB_SARADC, the RTC peripherals other than SENS) and radio blocks answer polls without being modelled | `src/devices/` | **Implemented**; register behaviour from QEMU's models ([spec](docs/qemu-devices.md)) and the TRM, with documented differences: real CPU clock selection, flash coherent with the cache, I2C and GPIO modelled |
| SAR ADC1 and ADC2 one-shot (SENS, 0x6000_8800..0x6000_8A00): registers read back, read-only status fields read 0; a rising edge of MEAS1_START_SAR completes a conversion at once (MEAS1_DONE_SAR set, MEAS1_DATA_SAR: the input `mv` sits at `v` on the converter's line where `v - deviation(v) = mv`, the code is `round(v × cal_code / 850)` clamped to 4095, `cal_code = round(850 × 4095 / full_scale)` with full scale 950/1250/1750/3100 mV for SAR_ATTEN1 0-3 and `deviation` the polynomial of the ESP32-S3 curve-fitting calibration per ADC and attenuation, so the curve-fitting calibration maps codes back to the input); the eFuses hold calibration version 1 with those codes at 850 mV (`Efuse::with_mac`); with no pad in SAR1_EN_PAD (the calibration channel 15 does not fit the 12-bit field) the input is a 1100 mV reference; the host sets each channel's input (`Peripherals::sens`, `Sens::set_adc1_mv`). ADC2 converts the same way (MEAS2_CTRL2, SAR_ATTEN2) with its channels at 0 V. The temperature sensor converts when TSENS_DUMP_OUT is set: TSENS_READY rises with TSENS_OUT = `round((t + 20.52) / 0.4386)` for the die temperature `t` (`Sens::die_temp_c`, 40 °C by default). Touch, ULP and the RTC_CORE/APB_ADC completion interrupts are **Unsupported** (the one-shot driver sees DONE before it would wait for them) | `src/devices/sens.rs` | **Implemented**; **Unit-tested** (`esp32s3_adc1_oneshot_codes`, `esp32s3_rtc_periph_around_sens_stays_write_only`, `the_temperature_sensor_reads_the_die_temperature`); register layout from the `esp32s3` PAC 0.37.0; the linear transfer function is a model, not calibrated against silicon (A10) |
| GDMA OUT channels: OUTLINK_START/RESTART read the descriptor chain from internal SRAM (D-bus, OUTLINK_ADDR completed with 0x3FC0_0000), buffers and descriptors in internal SRAM or in PSRAM pages mapped in the data window (a buffer may cross pages that map consecutive PSRAM pages), OUT_DSCR_ERR for a descriptor or buffer elsewhere or a CPU-owned descriptor under OUT_CHECK_OWNER, owner write-back (OUT_AUTO_WRBACK), FIFO status non-empty while data waits, OUT_DONE/OUT_EOF/OUT_TOTAL_EOF when the peripheral has sent the data (OUT_EOF at read time with OUT_EOF_MODE 0), OUT_EOF_DES_ADDR, OUT_STATE/OUT_DSCR*, interrupt sources 71-75. IN channels are register storage (sources 66-70 never rise). Only LCD_CAM consumes OUT data | `src/devices/gdma.rs`, `src/machine/bus.rs` (`DmaBus`) | **Implemented**; **Unit-tested** (`esp32s3_gdma_chain_drives_lcd_transfer`, `esp32s3_gdma_descriptor_errors`); register layout from the PAC; chain read in one step at OUTLINK_START, owner bits written back then (A9) |
| LCD_CAM, LCD side in I8080 mode: LCD_START runs the command phase (LCD_CMD, one or two words), the dummy cycles and the data phase (LCD_DOUT; all the GDMA data with LCD_ALWAYS_OUT_EN, else LCD_DOUT_CYCLELEN + 1 cycles) from the OUT channel whose OUT_PERI_SEL is LCD_CAM (5); one LCD_PCLK cycle per command word, dummy cycle and data byte (16-bit word with LCD_2BYTE_EN), LCD_PCLK from LCD_CLOCK (XTAL 40 MHz, PLL/2 or 160 MHz, fractional LCD_CLKM divider, LCD_CLKCNT_N, LCD_CLK_EQU_SYSCLK); at the end LCD_START clears, LCD_TRANS_DONE rises (source 24) and the transfer is queued for the host (`Peripherals::lcd_cam`, `LcdCam::out`, `LcdWrite { cmd, data }`); clearing LCD_START or setting LCD_RESET stops it after the cycles sent; LCD_UPDATE, LCD_RESET and LCD_AFIFO_RESET self-clear; byte and bit order options. RGB (DPI) mode, setup/hold cycles and the camera side are **Unsupported** | `src/devices/lcd_cam.rs` | **Implemented**; **Unit-tested** (`esp32s3_gdma_chain_drives_lcd_transfer`, `esp32s3_lcd_16bit_data_without_command`, `esp32s3_lcd_start_cleared_stops_after_sent_cycles`); not yet exercised by a firmware run (**Unknown** until an ST7789 board run shows frames) |
| Wi-Fi MAC (0x6003_3000..0x6003_6000, source 0): transmit queues (PLCP0 at 0xd08 - 8q, completion in 0xcb0, result in the PMD), receive descriptor list (base 0x088, next 0x08c, last 0x090, reload bit 0 of 0x084) with the 48-byte receive header, interrupt status 0xc3c and clear 0xc40, TSF latch and reset, MAC ready bit, MAC reset through APB_CTRL WIFI_RST_EN; every transmission succeeds 300 µs after it starts. Crypto engine for CCMP: key slots at 0x1400 + 40 × n (address, configuration, key), enabled in 0x814; a frame sent with the Protected bit (holding the CCMP header the driver wrote) is encrypted with the key slot of PLCP1 bits 21:17 and gets its MIC, which PLCP1 counts; a protected frame received is decrypted with the pairwise slot of its transmitter, or the group slot of its key ID, on an interface the frame is for, and handed over with its CCMP header and MIC; one that fails is dropped. The radio is **Unsupported** (its registers answer the calibration polls), as are TBTT and TSF timer interrupts, WEP, TKIP, GCMP, protected management frames, retries and errors | `src/devices/wifi_mac.rs`, [map](docs/wifi-mac.md) | **Implemented**; **Unit-tested** (`a_started_slot_sends_its_frame_and_completes`, `frames_fill_the_receive_list_then_wait_for_a_reload`, `the_tsf_counts_microseconds_from_its_reset`, `protected_frames_are_sealed_and_opened_with_the_key_slots`); register map from traces and disassembly of the Wi-Fi libraries; **Run-demonstrated** with esp-miner-rs (scan, association, DHCP, DNS, TCP both ways, pool session, web interface) and, under WPA2, with esp-miner-rs and ESP-Miner v2.15.4 (handshake, DHCP, pool session, AxeOS) |
| AES accelerator (0x6003_A000), typical mode: TRIGGER transforms TEXT_IN into TEXT_OUT at once with the key of KEY (MODE 0-2 encrypt with AES-128/192/256, 4-6 decrypt; little-endian words of the byte stream), STATE reads idle. DMA mode is **Unsupported** (its trigger does nothing) | `src/devices/aes.rs` | **Implemented**; **Unit-tested** (`the_fips_197_blocks`); register layout from the `esp32s3` PAC 0.37.0; **Run-demonstrated**: ESP-IDF's WPA2 supplicant unwraps the group key with it |
| Network (`net`): access point, open or WPA2-Personal (beacons, probe responses, open authentication, association, data frames bridged to Ethernet; under WPA2 the RSN element and Privacy bit, association refused (status 40) without a CCMP/PSK RSN element, the 4-way handshake with the group key, each message retried every second four times then deauthentication with reason 15, and CCMP data frames, pairwise key 0 and group key 1, replays dropped; `net::wpa`: PMK, PRF, PTK, EAPOL-Key MIC, AES key wrap, CCMP), router behind it on smoltcp 0.14 (DHCP, ARP for the gateway, DNS forwarded to the host resolver, UDP and TCP NAT through host sockets), client of the chip's own access point (probe, authentication, association, DHCP), host TCP ports forwarded to the chip through whichever is connected. WPA3 (SAE), WPA2-Enterprise and group rekeying are **Unsupported** | `src/net/` | **Implemented**; **Unit-tested** (`a_station_scans_authenticates_associates_and_sends_data`, `a_wpa2_station_runs_the_handshake_then_exchanges_ccmp_frames`, `a_wrong_passphrase_ends_in_a_handshake_timeout`, `dhcp_offers_then_acks_the_guest_address`, `udp_goes_out_through_a_host_socket_and_back`, `frames_round_trip`; `net::wpa` against the IEEE 802.11 PSK, PRF-512 and CCMP test vectors and RFC 3394); **Run-demonstrated** with esp-miner-rs and ESP-Miner v2.15.4 through bitaxe-emu-rs |
| Boot | `esp32s3-run` | **Boot-demonstrated**: the esp-miner-rs Bitaxe Gamma image boots through the ROM, the 2nd-stage bootloader (image SHA-256 check by the SHA accelerator) and the application, which runs its tasks (settings from NVS, WiFi access point stack, I2C devices, ASIC chain on UART1), with no unexpected exception. The ESP-Miner v2.15.4 factory images (ESP-IDF 6.0.2, both cores, octal PSRAM) boot the same way, find the 8 MB PSRAM (its memory test passes), start APP_CPU and FreeRTOS on both cores, and, on the bitaxe-emu boards, run to mining (regulator, fans, display, ASIC chain detection and frequency ramp, jobs) |

The register behaviour of Espressif QEMU's ESP32-S3 device models is written up in
[docs/qemu-devices.md](docs/qemu-devices.md).

## Assumptions

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| A3 | Internal SRAM is one physical memory seen at 0x3FC8xxxx (D-bus) and 0x4037xxxx (I-bus) | ESP32-S3 TRM memory map; the `esp-hal` linker leaves a DRAM gap for IRAM code (`.rwdata_dummy`) | SRAM model with aliases | Code written through D-bus then executed through I-bus | TRM table, then a test image that writes code via D-bus and calls it via I-bus, on a real board | retained (to confirm against TRM) |
| A4 | An instruction-count time base is enough for the firmware's timing loops | GSC/S5L precedent; `esp-hal` uses SYSTIMER/TIMG for time | §4.3 time model | Busy-wait calibration against CCOUNT, `ets_delay_us`, watchdog margins | M3 examples' delays within tolerance; WDT doesn't fire during normal runs | retained |
| A6 | The ROM image can be used locally but not committed | No license file next to `pc-bios/esp32s3_rev0_rom.bin` | §4.6 two ROM modes | — | Espressif's published terms for ROM images (to look up) | retained |
| A7 | An ELF boot that recreates the 2nd-stage bootloader's state is enough for `esp-hal` apps | QEMU `-kernel` mode and `esp-hal`'s own startup code | P4 boot | Apps reading bootloader-written registers (cache config, RTC state, WDT state) | M3 images print as on hardware; compare the MMIO report against a full flash boot (P8) | retained |
| A9 | Reading a GDMA OUT chain at OUTLINK_START (data and owner write-back in one step) is indistinguishable for drivers that do not touch the buffers before the transfer ends | `esp-hal` 1.2.2 i8080 and DMA buffer code: descriptors are prepared before OUTLINK_START and handed back after LCD_START clears | GDMA model | A driver that appends descriptors or edits buffers while the channel runs | A firmware that streams (circular chains, OUTLINK_RESTART) shows stale data | retained |
| A10 | Each SAR ADC follows the line through the origin and its eFuse calibration point (850 mV) up to the full scale of the attenuation, apart from the deviation polynomial of the ESP32-S3 curve-fitting calibration; the eFuses of a chip hold calibration version 1; the calibration channel samples a 1100 mV reference | ESP-IDF 6.0.2 and `esp-hal` 1.2.2 both read calibration version 1 from BLOCK2 and correct readings with that polynomial | SENS and eFuse models | Real chips scatter around the polynomial and their calibration codes differ from chip to chip | Compare the eFuse summary and codes of a real Bitaxe ESP32-S3 against a known voltage | retained |
| A11 | On a 16-bit LCD bus each cycle carries the two bytes of a little-endian word, the lower address on `LCD_DATA[7:0]`; LCD_BYTE_ORDER swaps them | LCD_USER field descriptions of the `esp32s3` PAC 0.37.0; no capture yet | `LcdWrite::data` order | RGB565 colour buffers on a 16-bit bus | Logic-analyzer capture of a 16-bit i8080 board | retained |
| A12 | An i8080 transfer takes one LCD_PCLK cycle per command word, dummy cycle and data cycle, with no setup or hold cycles | LCD_USER/LCD_MISC field descriptions of the PAC; the requested timing (4 MHz, 6400 bytes ≈ 1.6 ms) | LCD transfer end time | LCD_VFK/VBK_CYCLELEN set to large values | Capture of WR on a real board | retained |
| A13 | Running the two cores one after the other in each time slice (up to 2000 instructions each) is indistinguishable for firmware that synchronises them with spinlocks (S32C1I), shared memory and FROM_CPU interrupts | ESP-IDF SMP uses those mechanisms only | dual-core runs | handshakes timed in cycles between the cores | a firmware waiting for the other core within a few hundred cycles times out | retained |
| A14 | The octal PSRAM is an 8 MB AP Memory device (MR1 vendor 0x0D, MR2 density 3, generation 3) that returns what was written at every timing setting | the N16R8 modules of the Bitaxe boards; ESP-IDF 6.0.2 reads MR0-MR8 and checks the vendor | PSRAM init and memory test | MSPI timing tuning finds every point passing and falls back to its default point ("tuning fail") | compare the PSRAM log lines with a real board | retained |

## Licence

MIT or Apache-2.0, at your option.
