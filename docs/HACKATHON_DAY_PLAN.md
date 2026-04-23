# Hackathon Day Plan — Hour by Hour

This is what the 48-72 hours before and during the Athernex finals should look like. Print this. Tape it to the wall. Tick boxes.

---

## 3 days before (preparation)

### Afternoon (3 hours)
- [ ] Clone the `vendorguard-ai` repo on every teammate's laptop
- [ ] Install requirements. Run the stack. Confirm demo works on each machine.
- [ ] Each teammate reads `docs/MASTER_GUIDE.md`, `PITCH_SCRIPTS.md`, `JUDGES_QA.md` start to finish

### Evening (2 hours)
- [ ] Sign up for free-tier API keys — Shodan, VirusTotal, Anthropic (takes ~1 hour)
- [ ] Create `.env` with the keys you got. Re-run the demo — note the difference
- [ ] Set up Twilio WhatsApp sandbox. Link your own WhatsApp to the sandbox number
- [ ] Record first draft of the backup demo video (60 min)

---

## 2 days before

### Morning (3 hours)
- [ ] Deploy backend to Fly.io (see `DEPLOYMENT.md`)
- [ ] Deploy frontend to Vercel
- [ ] Update `window.VG_API` to point at Fly.io URL
- [ ] Test the deployed version end-to-end on 4G (phone hotspot). Timings ok?

### Afternoon (2 hours)
- [ ] Fix the deck using `DECK_FIX.md`. Export as PDF. Upload to the hackathon portal as the updated submission if allowed.
- [ ] Create the GitHub repo (public). Push. Add a clean README with screenshots. *This is your resume artefact.*

### Evening (3 hours)
- [ ] Full rehearsal: pitch + live demo + Q&A 3 times
- [ ] Have a friend play a hostile judge — use questions from `JUDGES_QA.md`
- [ ] Rerecord the backup video (final take). Upload to YouTube unlisted.

---

## 1 day before

### Morning (2 hours)
- [ ] Full team rehearsal — all 3 together. 3 clean runs.
- [ ] Identify the top 2 weaknesses in the pitch. Rewrite those 30 seconds.
- [ ] Print: pitch script, 10 FAQ answers, repo README, backup video URL, team emails

### Afternoon (1 hour)
- [ ] Pack: laptop, charger, HDMI/USB-C dongle, USB drive with repo + video, 2 pens, water
- [ ] Verify you can screen-share via HDMI (borrow someone's TV to test)
- [ ] Verify all three team-mates can unlock each other's laptops (shared demo password) in case primary laptop fails

### Evening
- [ ] Early dinner. No late-night debugging. If it doesn't work now, it won't work tomorrow.
- [ ] Bed by 11 PM. Full 8 hours.
- [ ] Alarm set for 2 alarms, 10 min apart

---

## Hackathon day

### 2 hours before your slot
- [ ] Arrive at venue. Find a power outlet. Plug in.
- [ ] Connect to venue WiFi. Test `ping 8.8.8.8`. If flaky, switch to hotspot.
- [ ] Open 3 terminals + 1 browser per `DEMO_RUNBOOK.md` setup. Pre-warm the scan.
- [ ] Hit F11 in the browser — full-screen mode. Test your deck on the projector if available.
- [ ] Mute Slack, WhatsApp, email notifications. Do-Not-Disturb on.
- [ ] Last rehearsal — whisper-mode in a corner. Full pitch + demo.

### 20 minutes before your slot
- [ ] Bathroom.
- [ ] Water. Don't drink too much — you don't want to be fidgety on stage.
- [ ] One full run of the demo sequence. Cache everything.
- [ ] Close every unnecessary tab, app, window. Only show what judges should see.
- [ ] Take a 60-second deep-breathing break. 4-7-8 breathing: inhale 4, hold 7, exhale 8.

### 5 minutes before
- [ ] Stand up. Shake out arms. Roll shoulders.
- [ ] Say the one-line pitch aloud. Say it again. Say it a third time.
- [ ] Remind team: hand-off points. Who speaks which slide.

### During the pitch
- [ ] Breathe between slides
- [ ] Look at the nodding judge
- [ ] Pause 2 full seconds after "contained in 3.15 seconds"
- [ ] End on a question, not a statement

### After the pitch (Q&A)
- [ ] If you know the answer, answer crisply in ≤25s (see `JUDGES_QA.md`)
- [ ] If you don't know, say so: "Let me follow up with specifics by email." Never bluff.
- [ ] If a judge asks something adversarial, thank them genuinely: "That's the right objection — here's how we think about it…"
- [ ] Never argue. Never get defensive. Always stay curious.

### After your slot
- [ ] Thank the judges by name if possible. Exchange contact if appropriate.
- [ ] Do NOT go back and rehash what you wish you'd said. It's over. Move on.
- [ ] Watch other teams present. Take notes on what works and what doesn't.

---

## Results announcement

### If you win
- [ ] Photos. Hug. Thank everyone.
- [ ] Collect every judge's contact on LinkedIn within 24 hours
- [ ] Ask for written feedback ("any one thing we could improve?")
- [ ] Share winning screenshot on LinkedIn within 48 hours — tag Athernex, DSCE, BMSCE
- [ ] Post on Reddit r/India, r/Bangalore — traction is advertising

### If you don't win
- [ ] Ask the winning team what they thought worked. Take notes. Do not sulk.
- [ ] Ask judges for 5 minutes of feedback. *"What would you change if you were us?"*
- [ ] Go home. Sleep. Tomorrow, post on Medium: *"We built a DPDP vendor risk platform in 48 hours — here's what we learned."*
- [ ] Submit to the next hackathon in 2 weeks. **The product is the same; the deck is now battle-tested.** You win the second one.

---

## Final reminder

The winning team is the team that:

1. **Ships a thing that works** — you have this
2. **Tells a story in 3 minutes** — you've rehearsed this
3. **Handles Q&A without panic** — you've prepped for this
4. **Doesn't fall apart when something glitches** — you have a backup plan

All four are checkboxes. Go execute the checkboxes. The outcome follows.
