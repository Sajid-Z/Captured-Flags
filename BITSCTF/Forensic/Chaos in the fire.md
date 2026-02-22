# Chaos in the Wire — CTF Writeup

## Challenge Info

- **Category:** Forensics
- **File:** `chaos.pcap`
- **Statement:**
  > Intelligence reports indicate that sensitive material is being quietly exfiltrated beyond national borders. At first glance, everything appears ordinary — HTTPS sessions, random-looking data, standard TCP behavior — but analysts believe the transfer mechanism does not rely on the application layer at all. Nothing in the payloads appears readable. Yet the data left the country successfully. This is the first time this has happened in **32 years**.

---

## Step 1: Initial Recon — Open the PCAP

Open `chaos.pcap` in Wireshark or use `tshark`:

```bash
tshark -r chaos.pcap -c 20
```

You'll see:
- A short **HTTP exchange** (packets 1–5): a client fetches `/network_notes.txt` from `10.0.0.80`.
- Then **2500+ packets** from various random source IPs → `10.0.0.80` on **port 443** (SSL/TLS), all flagged as `Continuation Data` or `[PSH, ACK]`.

**Key observation:** The source IPs change on every single packet. That's unusual — normal HTTPS sessions maintain a consistent source IP.

---

## Step 2: Read the Hint — `network_notes.txt`

Extract the HTTP response payload:

```bash
tshark -r chaos.pcap -Y "http" -T fields -e http.file_data
```

Decode the hex output:

```bash
echo "<hex_output>" | xxd -r -p
```

You get:

> **Understanding TCP Internals**
>
> Sequence numbers and acknowledgements are **32-bit** values.
> IPv4 addresses are also **32-bit** integers when represented numerically.
> Sometimes **metadata carries meaning beyond its intended purpose**.

This tells you:
1. The covert channel is in **32-bit TCP/IP header fields** (not the payload — matching the challenge statement).
2. The relevant fields are: **source IP address**, **TCP sequence number**, and **TCP acknowledgment number**.
3. "32 years" in the challenge statement = **32-bit** values.

---

## Step 3: Identify the Covert Channel

Extract the three 32-bit fields from the covert traffic (packets going to port 443):

```bash
tshark -r chaos.pcap -Y "tcp.dstport==443" -T fields \
  -e ip.src -e tcp.seq_raw -e tcp.ack
```

You'll notice:
- **Source IPs** are different for every packet (random-looking).
- **Sequence numbers** are random-looking 32-bit values.
- **Acknowledgment numbers** are also random-looking 32-bit values.

None of these fields individually decode to anything readable. The trick is to **combine them**.

---

## Step 4: XOR the Fields Together

The key insight: the source IP is being used as a **one-time key** to XOR-encrypt two data streams:

| Bytes per packet | Formula |
|---|---|
| First 4 bytes | `source_IP ⊕ sequence_number` |
| Next 4 bytes  | `source_IP ⊕ ack_number` |

Write a Python script to extract this:

```python
from scapy.all import rdpcap, TCP, IP
import struct, socket

packets = rdpcap("chaos.pcap")

output = b''
for pkt in packets:
    if TCP in pkt and pkt[TCP].dport == 443:
        ip_int = struct.unpack("!I", socket.inet_aton(pkt[IP].src))[0]
        seq = pkt[TCP].seq
        ack = pkt[TCP].ack
        output += (ip_int ^ seq).to_bytes(4, 'big')
        output += (ip_int ^ ack).to_bytes(4, 'big')

with open("extracted.7z", "wb") as f:
    f.write(output)
```

---

## Step 5: Verify — It's a 7z Archive

```bash
file extracted.7z
# Output: 7-zip archive data, version 0.4
```

The first bytes `37 7A BC AF 27 1C` are the **7z magic number**. This confirms the XOR approach is correct.

---

## Step 6: Extract the Archive

```bash
7z x extracted.7z -o./extracted
```

Inside the `chaos_source/` folder you'll find **200 small ELF executables** (each ~14 KB) with random-looking filenames.

---

## Step 7: Run the Executables

Each binary outputs exactly **2 characters** when run:

```bash
cd extracted/chaos_source
chmod +x *
./0B1J7ITlqorY    # outputs: "bo"
./0HTHbi          # outputs: "d "
```

200 files × 2 chars = 400 characters total — a message with the flag embedded in it.

---

## Step 8: Find the Correct Order

The files need to be reassembled in **chronological order by modification timestamp** (oldest first):

```bash
ls -lt --time-style=+%s -r | grep -v "^total" | awk '{print $NF}' \
  | while read f; do ./"$f" 2>/dev/null; done
```

This outputs:

> Memory is a funny thing. When I was in the scene, I hardly paid it any mind. I never stopped to think of it as something that would make a lasting impression, certainly never imagined that eighteen years later I would recall it in such detail. I didn't give a damn about the scenery that day.**BITSCTF{v0l4t1l3_junk_m4th_c4nt_h1d3_th3_trutH}** I was thinking about myself. It was the age, that time

---

## Flag

```
BITSCTF{v0l4t1l3_junk_m4th_c4nt_h1d3_th3_trutH}
```

---

## Concepts Used

| Concept | Where |
|---|---|
| **Covert channel in TCP/IP headers** | Data hidden in src IP, seq#, ack# — not in the payload |
| **XOR encoding** | `source_IP ⊕ seq` and `source_IP ⊕ ack` recovers the original data |
| **File carving** | Extracted bytes form a valid 7z archive |
| **Timestamp-based ordering** | 200 ELF binaries must be sorted by mtime to reconstruct the message |
| **Binary analysis** | Each ELF outputs a 2-char fragment of the flag message |
