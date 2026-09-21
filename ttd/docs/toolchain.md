# Pinned toolchain

Reproducible builds require these to be pinned, not floating (`@latest` is
banned on release pipelines — Rencana V1 §10.2). Bump deliberately and note it
here.

| Tool | Pinned version | Used for |
|---|---|---|
| Go | `1.27.0` | all modules (`go.mod` / `go.work`) |
| `github.com/digitorus/pdfsign` | `v1.0.0-rc2` (commit `39f87fec7e33af3e3daa77f6fa86820b813036d5`) | PDF + crypto engine, ML-DSA |
| `github.com/skip2/go-qrcode` | `v0.0.0-20200617195104-da1b6568686e` | signature-appearance QR |
| `golang.org/x/mobile` (gomobile/gobind) | `v0.0.0-20260821190718-4776eadac327` | Android AAR bind (`apps/android/build-aar.sh`) |
| Android NDK | `r27` (`27.1.12297006`) — any that supports API 21..35 | gomobile native cross-compile |
| Android min native API | `29` | `gomobile bind -androidapi 29` |
| Gradle | `8.11.1` (wrapper committed under `apps/android/`) | Android APK build |
| Android Gradle Plugin | `8.7.3` | `apps/android/build.gradle.kts` |
| Kotlin (`kotlin.android`) | `1.9.24` | Android app |
| Android `compileSdk` / `targetSdk` | `36` / `36` (platform `android-36`, build-tools `36.0.0`) | `apps/android/app/build.gradle.kts` |
| OpenSSL (lab PKI path) | `3.5.x` (must list `ML-DSA-*` under `list -signature-algorithms`) | `pki/scripts/gen-lab-root-ca.sh` |
| JDK | `17` (Temurin) | Android build |

## First AAR build result (M1, §10.2)

* Host: windows/amd64, Go 1.27.0, NDK r27.
* Output: `apps/android/app/libs/pqcsign.aar` (~6.3 MB) with
  `jni/arm64-v8a/libgojni.so` and
  `id.example.pqcsign.mobilebridge.Mobilebridge` exposing
  `generateKey / exportPublicKey / createCSR / signPDF / verifyPDF`.
* Still pending: run generate/sign/verify on a physical arm64 device and
  record time + memory + a logcat/network capture proving no key leakage
  (needs a device connected via `adb`).

## Debug APK build result (M1)

* `apps/android/` Gradle project + committed wrapper (8.11.1); `./gradlew
  :app:assembleDebug` → `app/build/outputs/apk/debug/app-debug.apk` (~19 MB,
  `lib/arm64-v8a/libgojni.so`, offline, no INTERNET permission).
* `:app:generateSpikeFixtures` runs `pqcsign-cli genpki` to populate
  `app/src/main/assets/` (needs Go on PATH); fixtures are git-ignored.
* App = one screen: **Jalankan spike** runs keygen-on-device + sign + verify +
  tamper/wrong-root rejection and prints timings + the verification JSON;
  **Simpan signed.pdf** exports for Windows cross-check.
