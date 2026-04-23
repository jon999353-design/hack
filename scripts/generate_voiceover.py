#!/usr/bin/env python3
"""Generate the VendorGuard AI demo voiceover MP3 via Sarvam.ai Bulbul v3.

Reads docs/DEMO_SCRIPT.md, strips the [CUE: ...] stage directions, splits the
prose into Sarvam's 2500-character request limit, calls the text-to-speech
REST API, and stitches the returned base64 WAV chunks into a single MP3 at
out/demo-voiceover.mp3. Intended voice: 'abhilash' (male, Indian English) —
override with SARVAM_SPEAKER env var.

Usage:
    export SARVAM_API_KEY=...
    python scripts/generate_voiceover.py

Dependencies: standard library + ffmpeg (for the final WAV→MP3 concat step).
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO / "docs" / "DEMO_SCRIPT.md"
OUT_DIR = REPO / "out"
OUT_WAV = OUT_DIR / "demo-voiceover.wav"
OUT_MP3 = OUT_DIR / "demo-voiceover.mp3"

ENDPOINT = "https://api.sarvam.ai/text-to-speech"
MODEL = "bulbul:v3"
SPEAKER = os.environ.get("SARVAM_SPEAKER", "priya")  # female Indian English (bulbul:v3) — clearest diction
LANGUAGE = "en-IN"
PACE = float(os.environ.get("SARVAM_PACE", "1.0"))
SAMPLE_RATE = 22050
MAX_CHARS = 2400  # Sarvam bulbul:v3 hard limit is 2500; leave a small cushion.


def extract_script(md_path: Path) -> str:
    """Pull the narrator prose out of DEMO_SCRIPT.md.

    The script body lives in a single fenced ``` block. Lines of the form
    ``[CUE: ...]`` are stage directions for the video editor, not for the
    narrator — strip them. Keep paragraph breaks intact so Sarvam can time
    breaths correctly.
    """
    text = md_path.read_text()
    match = re.search(r"```\s*\n(.*?)\n```", text, re.DOTALL)
    if not match:
        sys.exit(f"could not find a fenced script block in {md_path}")
    raw = match.group(1)
    # Drop [CUE: ...] lines and their trailing blank line, collapse >2 blank
    # lines to exactly 2 (one paragraph break).
    cleaned = re.sub(r"^\s*\[CUE:[^\]]*\]\s*\n?", "", raw, flags=re.MULTILINE)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
    return cleaned


def chunk_text(text: str, limit: int = MAX_CHARS) -> list[str]:
    """Split into <=`limit`-char chunks on paragraph boundaries so the TTS
    model gets natural pauses. Never mid-sentence."""
    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    chunks: list[str] = []
    buf = ""
    for p in paragraphs:
        candidate = (buf + "\n\n" + p).strip() if buf else p
        if len(candidate) <= limit:
            buf = candidate
            continue
        if buf:
            chunks.append(buf)
        # If a single paragraph exceeds the limit, split on sentences as a
        # fallback (rare for our 90-second script, but safe).
        if len(p) <= limit:
            buf = p
        else:
            sentences = re.split(r"(?<=[.!?])\s+", p)
            sub = ""
            for s in sentences:
                if len(sub) + len(s) + 1 <= limit:
                    sub = (sub + " " + s).strip() if sub else s
                else:
                    if sub:
                        chunks.append(sub)
                    sub = s
            buf = sub
    if buf:
        chunks.append(buf)
    return chunks


def tts_chunk(api_key: str, text: str) -> bytes:
    """POST one chunk to Sarvam, return decoded WAV bytes."""
    body = {
        "text": text,
        "target_language_code": LANGUAGE,
        "speaker": SPEAKER,
        "model": MODEL,
        "pace": PACE,
        "sample_rate": SAMPLE_RATE,
    }
    req = urllib.request.Request(
        ENDPOINT,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "api-subscription-key": api_key,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        sys.exit(f"Sarvam TTS {e.code}: {detail}")

    # Sarvam returns {"audios": ["<base64>"], ...}; decode the first segment.
    audios = payload.get("audios") or []
    if not audios:
        sys.exit(f"Sarvam response had no audios: {payload}")
    return base64.b64decode(audios[0])


def concat_wav(chunks: list[bytes], out_path: Path) -> None:
    """Stitch the returned WAV chunks head-to-tail by writing each to a temp
    file and piping through ffmpeg's concat demuxer. This preserves sample
    rate + channels without re-encoding."""
    if len(chunks) == 1:
        out_path.write_bytes(chunks[0])
        return
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        listing = tmp_path / "list.txt"
        parts = []
        for i, c in enumerate(chunks):
            p = tmp_path / f"part{i:02d}.wav"
            p.write_bytes(c)
            parts.append(p)
        listing.write_text(
            "\n".join(f"file '{p.resolve()}'" for p in parts) + "\n"
        )
        subprocess.run(
            [
                "ffmpeg", "-y", "-f", "concat", "-safe", "0",
                "-i", str(listing), "-c", "copy", str(out_path),
            ],
            check=True,
            capture_output=True,
        )


def wav_to_mp3(wav_path: Path, mp3_path: Path) -> None:
    subprocess.run(
        ["ffmpeg", "-y", "-i", str(wav_path), "-codec:a", "libmp3lame",
         "-qscale:a", "2", str(mp3_path)],
        check=True,
        capture_output=True,
    )


def main() -> None:
    api_key = os.environ.get("SARVAM_API_KEY")
    if not api_key:
        sys.exit("SARVAM_API_KEY env var not set")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    script = extract_script(SCRIPT_PATH)
    chunks = chunk_text(script)
    print(f"[tts] {len(script)} chars split into {len(chunks)} chunk(s); "
          f"speaker={SPEAKER}, pace={PACE}")

    wavs = [tts_chunk(api_key, c) for c in chunks]
    concat_wav(wavs, OUT_WAV)
    print(f"[tts] wrote {OUT_WAV} ({OUT_WAV.stat().st_size:,} bytes)")

    wav_to_mp3(OUT_WAV, OUT_MP3)
    print(f"[tts] wrote {OUT_MP3} ({OUT_MP3.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
