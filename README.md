# Input Capture & Encrypted Transfer Demo (Educational Only)

> WARNING: EDUCATIONAL / LAB USE ONLY

This repository contains a **proof-of-concept demo** that shows:

- How keyboard/mouse input can be captured on a local machine.
- How that data can be written to a file.
- How a separate script can read that file and send it using:
  - Symmetric encryption (AES) for confidentiality, and
  - Raw TCP packets (using Scapy) as a custom transport mechanism.
- How a receiver can listen on the network, reconstruct the payload, and decrypt it.

This code is provided **solely for educational and defensive purposes**: to help developers and security students understand how input capture and custom encrypted exfiltration channels can be implemented, so they can better defend against such techniques.

An extensive write-up of the writing process is included in the repo, which also contains analysis of Indicators of Compromise, used Tactics, Techniques and Procedures based on MITRE, and speculations on possible evolution of presented code would it be a real-world deployed and existing malware.

---

### Disclaimer on Stealth / Evasion Discussion

Parts of the accompanying write-up discuss how real malware might attempt  to hide its presence (e.g., obfuscation, evasion, anti-analysis). These sections are **purely analytical** and are included only to help readers  understand how such threats operate in the wild.

This repository does **not** include:
- Rootkit techniques
- Persistence mechanisms
- Privilege escalation
- Anti-forensic features
- Any code designed to bypass endpoint protection tools

All discussion is high-level and intended for cyber-security education only.

---

## Architecture

At a conceptual level, the demo is split into three parts:

1. **Input capture script - malware.py**
- Hooks into system input events to capture what is typed or clicked.
- Filters out certain keys and special combinations.
- Writes the resulting text lines into a local file.

2. **Sender script - sendover.py**
- Reads the local file contents.
- Encrypts the data using a symmetric key algorithm (AES in CBC mode).
- Encodes the result and sends it over a TCP connection using a crafted packet.
- Clears the local file after sending.

3. **Receiver script - receive.py**
- Listens for specific TCP packets on a chosen interface and port.
- Extracts the encoded payload from incoming packets.
- Decodes and decrypts the data using the same symmetric key.
- Prints the recovered plaintext.

These components are meant to illustrate **what is possible** and to help people think about how to detect and defend against similar behavior in real-world systems. **It has only been tested and hardcoded for host machine --> VM machine use.**

The repository also includes:

**Malware building process write-up**
- Explains how each of the modules and its contents follow modern malware trends.
- Explains all the obfuscation and descretion techniques a malicious actor may include in their software.
- Draws up concrete Indicators of Compromise one should look for to see if their system was a target for attack.
- Analyzes Techniques, Tactics and Procedures based on MITRE ATT&CK (https://attack.mitre.org).
- Explores possible evolutions of presented software to highlight commonly used techniques and what to be cautious of.
- Assumes a use process: emulates victim behaviour, exfiltrates the data from the source machine and receives it on the target machine.


---

## Intended Use Cases

Some legitimate use cases in a **controlled, consent-based environment**:

- Security research in a sandboxed lab.
- Demonstrations for a class or workshop about:
  - How keylogging techniques work,
  - How encrypted exfiltration can be implemented, and
  - Why host and network monitoring is important.
- Testing defensive measures such as EDR rules, IDS signatures, or host hardening techniques against this style of behavior.

If you are unsure whether a use case is legitimate, **assume it is not**.

---

## Legal & Ethical Notice

Using any form of input logging / interception software **without the explicit, informed consent** of all affected users is likely illegal in many jurisdictions and almost certainly unethical.

By using this code, you agree that you will:

- Only run it on machines you own or are explicitly authorized to test.
- Only run it in controlled lab environments or with clear, written permission from all users of the machine.
- Never use it to capture passwords, private messages, or any other sensitive information from unsuspecting users.
- Comply with all applicable laws, regulations, and institutional policies in your country.

The author of this code **does not accept any responsibility** for how third parties use (or misuse) it. This project is a learning tool, not a product, and the write-up document includes only speculations and analysis, not a tutorial for action.