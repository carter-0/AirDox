# AirDox

Two Apple-related Flipper Zero BLE sniffing demos:

- AirDox Sniffer (Deanonymise nearby AirDrop users)
- BLE Sniffer (Scan nearby Apple devices)

## Installation

This Flipper Application requires my [firmware fork](https://github.com/carter-0/flipperzero-firmware) because it uses the full BLE stack. More details in the repo.

### Simple

1. Follow the [firmware installation instructions](https://github.com/carter-0/flipperzero-firmware?tab=readme-ov-file#flipper-zero-firmware-my-ble-fork)
2. Download the .fap from [Releases](https://github.com/carter-0/AirDox/releases)
3. Copy the file onto your Flipper into `apps/Bluetooth`

### From source

Firmware:

1. `git clone https://github.com/carter-0/flipperzero-firmware`
2. `cd flipperzero-firmware`
3. Connect your Flipper Zero to your device
4. `./fbt updater_package COMPACT=1 DEBUG=1 COPRO_STACK_BIN=stm32wb5x_BLE_Stack_full_fw.bin COPRO_STACK_TYPE=ble_full`
5. `./fbt COMPACT=1 DEBUG=1 COPRO_STACK_TYPE=ble_full COPRO_STACK_BIN=stm32wb5x_BLE_Stack_full_fw.bin COPRO_OB_DATA=scripts/ob_custradio.data COPRO_DISCLAIMER=1 flash_usb_full`

App:

1. `git clone https://github.com/carter-0/AirDox`
2. `cd AirDox`
3. `ufbt update --local=/path-to-flipperzero-firmware/dist/f7-DC/flipper-z-f7-sdk-local.zip --hw-target h7`
4. `ufbt launch`

## AirDox Sniffer

Partially deanonymise nearby AirDrop senders by sniffing BLE packets with your Flipper Zero.

https://github.com/user-attachments/assets/37063ac0-6deb-41b1-8f15-672d0e883670

### Limitations

This app requires a shortlist of phone numbers to be effective (i.e. we can only deanonymise someone if we already know who they are.)

Example: loading your contacts into the app and detecting when someone in your contacts uses AirDrop nearby.

### Background

This app was supposed to fully deanonymise the phone number of any AirDrop user nearby, as a Flipper Zero implementation of the method described [here](https://eprint.iacr.org/2021/893.pdf).

Unfortunately, the full implementation of this requires AWDL (Apple Wireless Direct Link), which the Flipper Zero does not have the hardware for. Technically we could get it working with an attached ESP32, but it would require porting [OWL](https://github.com/seemoo-lab/owl) and a lot of other stuff far beyond what I'm capable of doing.

The first stage of AirDrop (figure below) involves the sender broadcasting BLE packets containing hashed versions of identifiers. Here is an example packet (AD-only):

```
4C 00 | 05 12 | 00 00 00 00 00 00 00 00 | 02 | 74 95 EF 93 DD C9 80 07 | 00 D2
└─┬─┘   └─┬─┘   └────────┬────────────┘   │    └────────┬────────────┘   └─┬─┘
  │       │              │                │             │                  └── Unknown
  │       │              │                │             └── Hashed contact data (8 bytes)
  │       │              │                └── Status/Type field
  │       │              └── Reserved/Padding (8 bytes)
  │       └── Apple AirDrop Service Type (0x1205)
  └── Apple Company ID (0x004C)
```

If we zoom in on the hashed contact data:
```
74 95 EF 93 DD C9 80 07
└─┬─┘ └─┬─┘ └─┬─┘ └─┬─┘
  │     │     │     └── Identifier D
  │     │     └── Identifier C
  │     └── Identifier B
  └── Identifier A
```

In this case, `Identifier C` is the hashed phone number, calculated as

```python
hashlib.sha256(phone_number.encode('utf-8')).hexdigest()[:16]
```

In previous versions of iOS, Apple always sent them in the order:

| Position | Identifier | Content |
|----------|------------|---------|
| A        | sha(AppleID) | Apple ID hash |
| B        | sha(phone)   | Phone number hash |
| C        | sha(email)   | Primary email hash |
| D        | sha(email2)  | Secondary email hash |

But empirically all devices after iOS ~15 randomise their order. I have not seen this documented anywhere online yet, but in theory it 4x'es the security of this stage, since we can no longer tell which identifier to brute force.

Anyway, since the number of issued phone numbers for a particular country is a limited, enumerable space, we can compute the identity of any AirDrop user to within ~5k phone numbers (in the UK at least).

That's not very useful on it's own, but when you already have a shortlist of candidates it can be enough to fully identify an AirDrop sender.

The idea is:

1. Upload `phonenumbers.txt` to your Flipper, in the format:
   ```
   +447728392917
   07463908720
   (etc, up to 1k entries)
   ```
   One phone number per line, format is standardised in-app (though only tested with UK numbers) so don't worry about cleaning.

2. Start AirDox Sniffer, choose your file. In the background we'll compute the truncated SHA256 hash for each phone number.

3. When someone nearby opens AirDrop, we cross reference the detected hashes with your list. If the sender was on your list, they'll be deanonymised.

## BLE Sniffer

A Flipper Zero port of [ble_read_state.py](https://github.com/hexway/apple_bleee/blob/master/ble_read_state.py) from [hexway/apple_bleee](https://github.com/hexway/apple_bleee)

https://github.com/user-attachments/assets/4c8cb239-aa03-4240-b93e-10f2748e9dfa

## Acknowledgements

This project wouldn've been possible without the work of:

[[1]](https://www.usenix.org/system/files/sec21-heinrich.pdf): PrivateDrop: Practical Privacy-Preserving Authentication for Apple AirDrop
Alexander Heinrich, Matthias Hollick, Thomas Schneider,
Milan Stute, and Christian Weinert, TU Darmstadt

[[2]](https://github.com/hexway/apple_bleee): Apple Bleee: Hexway, Dmitry Chastuhin, gelim, noplanman, CaptainStabs, cclauss

[[3]](https://petsymposium.org/popets/2020/popets-2020-0003.pdf): Discontinued Privacy: Personal Data Leaks in Apple Bluetooth-Low-Energy Continuity Protocols: Guillaume Celosia, Mathieu Cunche


## License

GNU General Public License v3.0 (compliant with licensing of hexway/apple_bleee)
