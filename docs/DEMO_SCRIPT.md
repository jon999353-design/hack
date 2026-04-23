# VendorGuard AI — 90-Second Demo Voiceover Script

Paced for a narrator speaking ~155 words/min. Cue-tagged to the Demo Mode panel transitions so the audio can be generated once and synced to any screen recording of `Ctrl+Shift+D`.

**Target length:** 85-95 seconds
**Target tone:** confident, technical, slightly urgent. Not salesy.
**Target voice (if OpenAI `tts-1-hd`):** `onyx` (male, authoritative) or `nova` (female, clean). For ElevenLabs, a trained Indian-English voice works best in front of Bengaluru judges.

---

## Full script

```
[CUE: Overview panel — trust score ring animating 0 → 12]

Every enterprise in India now runs on vendors. Your payments partner,
your CRM, your logistics API. And under the Digital Personal Data
Protection Act of 2023, a breach in any one of them is YOUR
liability — up to 250 crore rupees per section.

VendorGuard AI is the vendor access control plane for DPDP-compliant
India. Watch what it does in sixty seconds.

[CUE: Findings panel — eleven OSINT hits render, severity chips lit]

We just scanned paytrust-partner.com. Eleven findings from Shodan,
HaveIBeenPwned, crt-dot-sh, VirusTotal, DNS, TLS, and nuclei. A
weighted ensemble model gave it a trust score of twelve out of a
hundred. Block band.

[CUE: DPDP Exposure panel — clauses expand, ₹600 Cr counter climbs]

Here is where we go beyond every other vendor-risk tool. Every single
finding is mapped to a specific DPDP Act clause — section 5,
section 8(5), 8(6), and 8(8) — with the verbatim gazette excerpt,
the rupee penalty, and the data fiduciary's immediate action. Six
hundred crores of potential exposure on this one vendor, visible at
a glance.

[CUE: Gateway panel — Activate, then Simulate Attack fires, timer ticks]

Now the attack. A rogue vendor process tries to pull ten thousand
records. The IsolationForest anomaly detector and deterministic policy
engine catch it instantly. Wall-clock containment — measured, not
estimated — forty-three milliseconds. WhatsApp alert fired.
CERT-In six-hour incident report auto-drafted.

[CUE: Contract Intel panel — 17 rules render with red/amber/green + confidence]

Layer five: contract intelligence. Sixteen DPDP rules run over the
vendor's data processing agreement. Each verdict carries a confidence
score, the exact keyword and offset that triggered it, and a
ready-to-counter-sign rewrite grounded in the gazette quote.

[CUE: Remediation > Audit ZIP panel — download triggers]

One click. The complete DPDP audit evidence bundle — scan JSON,
playbook, alerts, board PDF, CERT-In Form A — zipped and ready to
hand to the Data Protection Board.

[CUE: Executive Board panel — KPIs land with glow animation]

Portfolio view. ₹ exposure under watch, ₹ saved by gateway blocks,
attacks auto-contained, ISO 27001 and SOC 2 control coverage.
Everything grounded in reproducible evidence. Run slash self-test at
any time — four benchmark DPAs, four green ticks. Not a black box.
A provable one.

[CUE: back to Overview panel]

VendorGuard AI. DPDP-native, not GDPR-retrofitted. Built for
Athernex 2026 by Team Rashi Innovators.
```

---

## Generation plan

1. Generate TTS using OpenAI `tts-1-hd` with voice=`onyx`, format=`mp3`, speed=`1.0`. Command (once `TTS_API_KEY` is set):
   ```bash
   python scripts/generate_voiceover.py  # writes demo-voiceover.mp3
   ```
2. Open the frontend against the local backend, trigger Demo Mode with `Ctrl+Shift+D`, record screen with `wf-recorder` or `ffmpeg x11grab` to `demo-video.mp4`.
3. Mux:
   ```bash
   ffmpeg -i demo-video.mp4 -i demo-voiceover.mp3 -c:v copy -c:a aac -shortest demo-final.mp4
   ```
4. Upload to YouTube as unlisted or keep as a local MP4 to play on stage if the projector has bad WiFi.

## Fallback if TTS fails

Record yourself (the team captain) reading this script into your phone's voice memo app. A real human voice is actually better than TTS — judges know TTS when they hear it. Use TTS only if you don't have a clean recording environment.
