# 🔎 ReconToolkit

A modular reconnaissance toolkit for bug bounty hunters, penetration testers, and CTF players.
It combines **passive** and **active** scanning strategies to give you maximum visibility into your targets.

---

## 🚀 Features

* 📡 **Passive Reconnaissance**

  * Subdomain enumeration
  * Alive host detection using `httpx`
  * Results saved to `ReconnResult/Alive_subs.txt`

* 🔨 **Active Reconnaissance**

  * Port scanning with `nmap`
  * Technology fingerprinting using `whatweb`
  * URL fuzzing and crawling with `katana`
  * Automatic parameter and link extraction
  * Results stored under `ReconnResult/`

* ✅ Automatically creates output folders and cleans extracted links.

---

## 🛠️ Requirements

Make sure these tools are installed and available in your `$PATH`:

```bash
# Python dependencies
pip install -r requirements.txt

# System tools
sudo apt install nmap whatweb

# Fot required tools 
go install github.com/haccer/subjack@latest                        # /Path Example/GO/bin/subjack
go install github.com/projectdiscovery/httpx/cmd/httpx@latest      # /Path Example/GO/bin/httpx
sudo apt install golang
git clone https://github.com/aboul3la/Sublist3r.git                # /Path Example/Sublist3r/Sublist3r.py
cd Sublist3r
pip install -r requirements.txt

# Then add each of this tools paths to $Path
echo 'export PATH=/The Full Tool Path/:$PATH' >> ~/.bashrc
echo 'export PATH=/The Full Tool Path/:$PATH' >> ~/.zshrc
```

---

## 📁 Folder Structure

```
ReconnResult/
├── Alive_subs.txt         # Alive hosts from passive recon
├── nmap_output.txt        # Port and service scan results
├── katana_output.txt      # Crawled URLs
├── parameters.txt         # Extracted parameters (e.g. ?id=)
└── cleanLinks.txt         # URLs with stripped query strings
```

---

## ⚙️ Usage

### 🕵️ Passive Recon (subdomain + alive check)

> Example: `passive.py`

```bash
python3 passive.py -d example.com -o ReconnResult/Alive_subs.txt
```

* `-d`: Target domain (e.g., `example.com`)
* `-o`: Output file to save alive subdomains

This script:

* Enumerates subdomains
* Pings them using `httpx`
* Saves alive domains to `ReconnResult/Alive_subs.txt`

---

### 🔨 Active Recon (port scan, fingerprinting, crawling)

> Example: `Reconn.py`

```bash
python3 Reconn.py -t example.com -f "-sS -Pn" -oH ReconnResult/Alive_subs.txt
```

* `-t`: Target IP or domain
* `-f`: Nmap flags (default: `-sS`)
* `-oH`: Path to alive subdomains list (e.g., from passive recon)

This script:

* Runs `nmap` with selected flags
* Fingerprints using `whatweb`
* Crawls URLs with `katana`
* Extracts parameters and cleans links automatically

---

## 📌 Example Workflow

```bash
# 1. Passive recon
python3 passive.py -d target.com -o ReconnResult/Alive_subs.txt

# 2. Active recon on the result
python3 scanner.py -t target.com -f "-sS -Pn" -oH ReconnResult/Alive_subs.txt
```

---

## 📑 Example Output Snippets

```txt
# parameters.txt
id
page
user

# cleanLinks.txt
https://example.com/home
https://example.com/products
```

---

## 🧠 Notes

* All scripts auto-create `ReconnResult/` if not found.
* Output is color-coded for easier reading.
* Designed to be modular — feel free to expand it!

---

## 🧑‍💻 Author

**Mostafa El-Sayed Mosaad Taha El-Badawy**
Ethical Hacker | Web Security Researcher | Bug Bounty Hunter
🔗 [GitHub Profile]((https://github.com/mostafa587)) <!-- (replace with your actual profile link) -->


---

## ⚠️ Disclaimer

This tool is for **educational purposes** and **authorized security assessments** only.
Always obtain proper permission before running any scan.
