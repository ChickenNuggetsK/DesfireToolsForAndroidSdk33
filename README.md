# desfire-tools-for-android
A collection of tools for interaction with [MIFARE DESFire EV1] NFC tags using Android, mostly adapted from [libfreefare] and [nfcjlib].

## Fork additions (ChickenNuggetsK) — NFC analysis toolkit

This fork turns the demo app into a small hands-on DESFire analysis toolkit. All features
were added on top of the MichaelsPlayground / SDK 33 fork and are reachable from the overflow
menu (⋮). The app uses NFC **reader mode**, so it behaves well on Xiaomi/MIUI where the system
otherwise steals the tag.

### Features added

- **Run Script** — paste commands, one per line (`#` and `//` comments ignored):
  - raw ISO 7816 / DESFire APDUs in hex, e.g. `90 6A 00 00 00`;
  - high-level commands backed by the embedded [nfcjlib] crypto session:
    - `SELECT <aid>` — select an application (3-byte AID, LSB first, e.g. `SELECT 01 00 00`)
    - `AUTH <keyno> <32 hex>` — AES mutual authentication
    - `READ <fileno> <offset> <length>` — read a file via the authenticated session
    - `CHFILESETTINGS <fileno> <comm> <ar1> <ar2>` — change a file's comm mode / access rights
  - responses are shown in a scrollable, copyable dialog (hex + ASCII).
- **Dict Attack** — pick a `.dic` wordlist (one AES key per line, 32 hex, `#` comments) and
  brute-force it against a chosen AID + key number; re-selects before each attempt and stops on
  success. Proxmark `mfdes_default_keys.dic` works (non-AES lines are skipped).
- **Dump + Restore** — reads a file's original settings, authenticates the Change key
  (default key configurable), opens read access, dumps the content, then restores the exact
  original settings and **verifies** the card is back to its initial state. Aborts untouched if
  authentication fails.
- **Ecran noir** — optional AMOLED "fake sleep": a full black overlay at minimum brightness
  while the screen stays on (so NFC keeps working). Tap to wake.
- **Armed actions** — the three tools above can be launched with no card present: they arm and
  fire automatically when a tag is tapped. The screen is kept on while armed/running, and a
  result produced during black-screen mode is deferred until you wake the screen.
- **Silent scanning** — `FLAG_READER_NO_PLATFORM_SOUNDS` disables the platform scan beep/vibration.
- **Crash fix** — a stale-tag `SecurityException` (common on MIUI) in the tag-presence scanner is
  now caught instead of crashing the app.

### Build & install

Builds run on GitHub Actions (`.github/workflows/build.yml`, JDK 17 / Gradle 8 / AGP 8). The
signed-with-debug-key APK is available:

- from the **Releases** page (attached `app-debug.apk`), or
- from any green **Actions** run → *Artifacts* → `desfire-tool-apk`.

Install it over any previous build (same debug signature). This is a personal, educational fork —
use it only on cards you own.

## Notes from MichaelsPlayground & AndroidCrypto

Note: This repository was forked from the original source available at:

https://github.com/skjolber/desfire-tools-for-android by Thomas Skjølberg (skjolber)

I changed as less as necessary to get the app run on modern Android SDK's - this app is running on SDK 33 and 
Gradle version 7.4.2. I know that there are a lot of "deprecated" notices in the source code but that could be 
the task for further enhancements. All credits are going to Thomas Skjølberg who created this fine piece of 
app in helping us to work with Mifare DESFIRE EV1 cards (b.t.w. the app is working on DESFire EV2 and EV3 as well :-).

One note regarding the file "MifareDesfireKey1.java" located in com.github.skjolber.desfire.libfreefare. The file 
equals to "MifareDesfireKey.java" in the original repository but as there is another file named "MifareDESFireKey.java"
(see the capitol letters "DES" compared to "Des") only one file can exist in a MacOS file system (I don't know about Windows, sorry). 
I renamed the file from "MifareDesfireKey.java" to "MifareDesfireKey1.java" and changed all references in the code to the 
new file name.

Second note: I included the "libfreefare" and "model" libraries direct into my package so they are no included within 
the build.gradle (app) file.

## The original description follows...

The original app in Google PlayStore: https://play.google.com/store/apps/details?id=com.skjolberg.mifare.desfiretool&hl=no

Features:
  * [MIFARE DESFire EV1] tag model
  * Encryption support
    * AES
    * (3)DES 
    * 3K3DES
  * [Mifare Desfire Tool] demo application

As NXP now has a freely available [TapLinx] SDK for supporting these cards, so this project is mostly for educational and/or debugging purposes.

## Licenses
For following licenses apply

  * nfcjlib - [Modified BSD License (3-clause BSD)]
  * libfreefare - [LGPL 3.0 with classpath exception]
  * everything else - [Apache 2.0]

# Obtain
The project is based on [Gradle].

# Usage
See the example application.

# History
 - 1.0.0: Initial version

[Gradle]:                               https://gradle.org/
[Apache 2.0]:          		            http://www.apache.org/licenses/LICENSE-2.0.html
[issue-tracker]:       		            https://github.com/skjolber/desfire-tools-for-android/issues
[Modified BSD License (3-clause BSD)]:  nfcjlib/LICENSE
[LGPL 3.0 with classpath exception]:    libfreefare/LICENSE
[Mifare Desfire Tool]:          		https://play.google.com/store/apps/details?id=com.skjolberg.mifare.desfiretool&hl=no
[TapLinx]:                              https://www.mifare.net/en/products/tools/taplinx/
[MIFARE DESFire EV1]:                   https://en.wikipedia.org/wiki/MIFARE#MIFARE_DESFire_EV1_(previously_called_DESFire8)
[libfreefare]:                          https://github.com/nfc-tools/libfreefare
[nfcjlib]:                              https://github.com/Andrade/nfcjlib
