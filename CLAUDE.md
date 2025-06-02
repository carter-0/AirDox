# AirDox

**AirDox** is a proof‑of‑concept Flipper Zero application that **sniffs AirDrop BLE advertisements** and immediately checks them against a user‑supplied list of phone numbers or e‑mails. If a match is found the identifier is shown on the Flipper’s screen in real time.

---

## How it works

1. **Passive BLE Scan** – The app cycles through advertising channels 37‑39 listening for Manufacturer‑Specific Data where `company‑ID = 0x004C` and `subtype = 0x12` (AirDrop).
2. **Token + Hash Extraction** – From each frame it pulls:
   - `identifierHashToken` (8 bytes) – the rolling salt Apple rotates ~15 min.
   - `shortHash` (5 bytes) – first 40 bits of `SHA‑256(token‖identifier)`.
3. **Dictionary Match** – Every time a beacon is received the app concatenates the token with each candidate identifier loaded from a `.txt` file, hashes it on‑device and compares the first 5 bytes. A 1 000‑entry list hashes in ≤ 10 ms on the Flipper’s STM32WB (≈10 000 cycles per SHA‑256).
4. **Display** – If a match occurs the corresponding phone number / e‑mail is pushed to the UI along with RSSI and a running timestamp.

---

## Features

- Real‑time matching; no pre‑computed tables required.
- **On‑device file picker** lets you select any UTF‑8 `<identifiers>.txt` on the SD‑card at runtime. Lines beginning with `#` are treated as comments.
- Handles token rotation automatically; simply keeps hashing with the new token as broadcasts arrive.
- Debounce logic to avoid duplicate notifications from the same device.

---

## Requirements

- Flipper Zero (stock or Unleashed firmware ≥ 0.92).
- MicroSD card containing a plain‑text dictionary (one identifier per line).
- `ufbt` build environment.

---

## Usage

1. Create `identifiers.txt` containing phone numbers or e‑mails (one per line).
2. Copy the file anywhere on the SD‑card (e.g. `/apps_data/airdox/`).
3. Launch **AirDox** → _Select Dictionary_ → choose your file.
4. The live capture screen shows packets per second, current token and any matched identifiers.

---

## Limitations

- BLE layer only – AirDox does **not** capture the Wi‑Fi/AWDL long‑hash.
- Designed for ≤ 5 000 identifiers; beyond that performance degrades below advert rate.

---

## Legal & Ethical Notice

Use responsibly. Broadcasting or processing personal identifiers without consent may violate privacy laws in your jurisdiction.
