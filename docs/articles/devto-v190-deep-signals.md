---
title: "Your firewall asks what left the machine. Mine asks whether you were there when it did."
published: true
tags: security, opensource, privacy, python
---

Every security tool on earth asks the same question: what is leaving this machine? After months of building Wiretap, I realized they all miss the deeper one - **was a human actually present when it left?**

5 MB uploaded to an AI provider while you type is you using your IDE. The same 5 MB at 2 PM while your machine sat idle through your lunch break is something else acting in your name. That single bit of context splits the world in two, and nothing in the industry reads it.

v1.9.0 ships four rounds of signals built on that insight. Everything below runs local-first, zero cloud, open source.

## 1. Presence-correlated exfiltration

Wiretap reads OS input-idle time - zero privileges: IOHID on macOS, GetLastInputInfo on Windows, xprintidle on Linux - and grades every sensitive outbound flow against it. Data leaving while you type: normal. Data leaving while you are away: `UNATTENDED_EXFIL`, critical.

The framing is honest: presence is evidence, not verdict. Your backup also uploads while you are away, and the alert says so. But the structural weakness of malware, rogue agents and compromised extensions is that **they do not need you to be there**. Until now, nothing measured that.

## 2. Flow DNA - the binary is the same, the behavior is not

A compromised process does not change its name. It changes its *metabolism*. Firefox that stops browsing and starts one sustained upload is not Firefox anymore, whatever the binary says.

Wiretap learns each process's network metabolism - burst sizes, inter-flow rhythm, out:in ratio, destination entropy (browsers spray, exfiltration funnels) - then scores drift in non-overlapping windows. The alert is literally explainable: "rhythm collapsed 4.2x, out:in ratio inverted, destinations funneled (entropy 3.3 to 0 bits)". Multi-feature drift is required, so watching a video (one feature) never fires - being compromised (all of them) does.

## 3. Persistence - where malware tells you it plans to stay

Every network-first tool misses the layer that matters most after infection: auto-start mechanisms. Wiretap enumerates LaunchAgents/Daemons, Run keys, systemd units, cron and autostart - no privileges needed - fingerprints every entry, and diffs over time. New auto-start entry pointing at `/tmp`? Critical. Entry deleted right after an incident? The cleanup is itself evidence.

On my own machine it found 19 auto-start entries and correctly flagged 3 interpreter-based ones (my own dev projects - exactly what an honest tool should surface for review).

## 4. Blast radius - impact assessment in milliseconds

When a critical alert fires, the only question that matters is "if this was malicious, what did it touch?" Today that answer takes a forensic expert hours. Wiretap computes it at alert time and ships it *inside the alert*:

```
Worst case: talked to 3 destinations; reached AI providers: Anthropic;
had 2 secret shape(s) in reach; SURVIVES REBOOT via auto-start;
held 21 files open
```

One triage sentence instead of an investigation. Every field labeled with its source and confidence; failures degrade to "unknown", never to silence.

## 5. Time-travel: what changed since Tuesday?

Hourly snapshots of the security-relevant state - persistence entries, listening ports, process shapes - diffed on demand. Appeared, vanished, mutated, risk-noted. The first question of every incident investigation, answered without a disk image.

## The system underneath

These signals feed a kill-chain correlator: three distinct detector families firing on the same entity within 15 minutes produce one composite critical incident - which can trigger automatic firewall lockdown (opt-in). And every alert is hash-chained into a forensic log: if an attacker deletes the evidence, the chain breaks, and **the deletion itself becomes the proof**.

Plus everything already shipped: AI traffic governance across 21 providers, MCP server risk audits (it found all 12 servers on my machine, correctly scoring the npx/uvx download-and-run ones), secrets egress watch, supply-chain install correlation, ransomware canaries, LAN honeyports, DNS firewall, network-aware profiles.

## Why this matters now

The AI era made every developer machine a concentrator of secrets - API keys in env vars, agents with full user privileges, MCP servers installed by copy-pasting JSON. The security tooling did not follow. Little Snitch and Portmaster are excellent at what they were designed for, but they were designed before any of this existed.

Wiretap is my answer: local-first, open source (PolyForm Shield), no account, no cloud, 414 tests, builds for macOS, Windows and Linux.

**Repo**: https://github.com/aiXisStudio/Wiretap - v1.9.0 released today. Stars, issues and adversarial review welcome. Especially the adversarial kind.
