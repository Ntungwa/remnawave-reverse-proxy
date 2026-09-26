<p aling="center"><a href="https://github.com/Ntungwa/remnawave-reverse-proxy">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="./media/logo.png" />
   <source media="(prefers-color-scheme: light)" srcset="./media/logo-black.png" />
   <img alt="Remnawave Reverse Proxy" src="https://github.com/Ntungwa/remnawave-reverse-proxy" />
 </picture>
</a></p>

<p align="center">
  <img src="./media/ru.png" alt="Русский" /> <a href="/README-RU.md">Русский</a> | <img src="./media/us.png" alt="English" /> <strong>English</strong>
</p>

---

[!CAUTION]
THIS REPOSITORY IS AN EDUCATIONAL EXAMPLE FOR LEARNING NGINX, REVERSE PROXY, AND NETWORK SECURITY BASICS. THIS SCRIPT DEMONSTRATES NGINX SETUP AS A REVERSE PROXY. NOT FOR PRODUCTION AND NOT FOR PRODUCTION USE! IF YOU DON'T UNDERSTAND HOW THE CONTROL PANEL WORKS - THAT'S YOUR PROBLEM, NOT THE SCRIPT AUTHOR'S. USE AT YOUR OWN RISK!

---

Overview

This automation script simplifies the deployment of a reverse proxy server using NGINX and XRAY, as well as the installation of Remnawave control panel and node. The architecture is optimized for performance: Xray runs directly on port 443, terminates TLS for every public hostname, and holds the certificate chain plus a static ECH keypair. The webserver behind Xray (NGINX or Caddy) listens on a Unix socket in cleartext, minimizing TCP overhead and improving connection reliability. The Xray inbound serves VLESS, Trojan and Shadowsocks across multiple transports (WebSocket, HTTPUpgrade, XHTTP, TCP+HTTP-obfs) on the same port, routed by path fallbacks.

[!IMPORTANT]
Debian and Ubuntu support. The script was tested in a KVM virtualization environment. For proper operation, you will need your own domains. It is recommended to run with root privileges on a freshly installed system.

Deployment Modes

The script supports flexible deployment configurations:

1. Single Server Mode

· Control panel and XRAY node installed on one machine
· Suitable for compact installations with moderate traffic

2. Distributed Mode

· Panel Server: Management center without XRAY node
· Node Server: Hosts XRAY node and the camouflage site on the direct domain

Domain Requirements

Prepare two domains or subdomains before installation:

1. CDN Domain: Panel UI at / and subscription page at /sub
2. Direct Domain: Proxy hostname, camouflage site, and ECH serverName

A separate subscription domain is optional and enabled by answering y to the split-subscription prompt during installation.

---

Domain Setup

The script supports two methods for obtaining SSL certificates:

· Cloudflare: Management through Cloudflare API
· ACME: Direct integration with hosting provider

Gcore and Bunny.net DNS APIs are also supported for wildcard issuance.

DNS Configuration Examples

Single Server Installation (panel + node together)

Record Type Name Value Proxy Status
A cdn.example.com your_server_ip Proxied
A direct.example.org your_server_ip DNS only

[!TIP]
The CDN domain may sit behind Cloudflare (proxied). The Direct domain must stay DNS only — Xray terminates TLS on it and ECH requires a direct handshake.

Distributed Installation (panel and node on different servers)

Record Type Name Value Proxy Status
A cdn.example.com panel_server_ip Proxied
A direct.example.org node_server_ip DNS only

---

Installation Guide

Single Server Deployment

1. Run the installation script
2. Select "Install Remnawave Components"
3. Select "Install panel and node on one server"
4. Enter the CDN domain, answer the split-subscription prompt (default N), enter the Direct domain
5. Wait for completion
6. The script will automatically restart services, display login credentials, and print the ECHConfigList to publish

Distributed Deployment

Step 1: Panel Server Setup

1. Run the installation script on the first server
2. Select "Install Remnawave Components"
3. Select "Install panel only"
4. Save the provided credentials and the printed ECHConfigList

Step 2: Certificate Export

1. Log in to the control panel
2. Navigate to Nodes → Management
3. Select the target node
4. Find the "Secret Key (SECRET_KEY)" field
5. Copy the certificate using the copy icon

Step 3: Node Server Setup

1. Run the installation script on the second server
2. Select "Install Remnawave Components"
3. Select "Install node only"
4. Enter the Direct domain and paste the certificate when prompted
5. Confirm the successful node connection message

---

Security Features

Panel Access Protection

NGINX configuration implements URL parameter-based authentication to protect against unauthorized discovery:

Access Method

```
https://cdn.example.com/auth/login?<SECRET_KEY>=<SECRET_KEY>
```

How It Works

1. URL parameter automatically sets a cookie in the browser
   · Cookie name: <SECRET_KEY>
   · Cookie value: <SECRET_KEY>
2. Access requirements:
   · Valid cookie must be present
   · URL must contain correct parameter
3. Failed access behavior:
   · Missing cookie: Blank page or 404 error
   · Incorrect parameter: Blank page or 404 error

This protection level prevents:

· Host scanning discovery
· Path brute-force attacks
· Brute-force access attempts

The panel remains invisible without the correct authentication parameter. Two alternative auth modes are offered at install time: TinyAuth (nginx, extra subdomain + certificate) and the Caddy auth portal (Caddy-only, built into the image, no extra domain required).

Transport Security

· TLS terminated by Xray on port 443
· ECH (Encrypted Client Hello) hides the SNI from passive observers
· Static ECH keypair — the client-facing configuration never changes, so client configs stay valid across panel and node updates
· Certificate hot-reload — certbot renewals restart remnanode through the deploy hook so Xray picks up the new files

---

Features

Proxy Server Configuration

· All-in-one Xray inbound on 443 covering VLESS, Trojan and Shadowsocks across WebSocket, HTTPUpgrade, XHTTP, and TCP+HTTP-obfs
· TLS terminated by Xray with static ECH enabled
· Automatic configuration updates via subscription
· JSON subscription support with format conversion for popular clients
· Compatibility with major proxy clients

NGINX Integration

· Optimized reverse proxy setup with XRAY
· Unix socket communication for reduced overhead
· Cleartext behind Xray — the webserver holds no certificate

Security Implementation

· Firewall: UFW configuration for access control
· SSL Certificates: Cloudflare / Gcore / Bunny / ACME with automatic renewal
· IPv6 Management: Vulnerability prevention measures
· TCP Optimization: BBR congestion control algorithm
· Masking: Random website template selection

---

Quick Start

Execute the following command to begin installation:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/Ntungwa/remnawave-reverse-proxy/refs/heads/main/install_remnawave.sh)
```

If GitHub is unreachable, use the jsDelivr mirror:

```bash
bash <(curl -Ls https://cdn.jsdelivr.net/gh/Ntungwa/remnawave-reverse-proxy@main/install_remnawave.sh)
```

<p align="center">
  <img src="./media/remnawave-reverse-proxy_en.png" alt="Installation Interface" />
</p>

---

[!CAUTION]
This repository is intended solely for educational purposes and for studying the principles of reverse proxy servers and network security. The script demonstrates proxy server configuration using NGINX for reverse proxy, traffic management, and attack protection.

We strongly remind you that using this tool to bypass network blocks or censorship is illegal in a number of countries where laws exist regulating the use of technologies to circumvent internet restrictions.

This project is not intended for use in ways that violate information protection laws or interfere with censorship mechanisms. We are not responsible for any legal consequences associated with using this script.

Use this tool/script solely for demonstration purposes, as an example of reverse proxy operation and data protection. We strongly recommend deleting the script after familiarization. Further use is at your own risk.

If you are unsure whether using this tool or its components violates the laws of your country - refrain from any interaction with this tool.

Community

Join our Telegram community for support and discussions:

Telegram chat: https://t.me/remnawave_reverse

Donations

If you like this project and want to support its further development, please consider making a donation. Your contribution helps fund future updates and improvements!

Donation Methods:

· TON USDT: UQAxyZDwKUPQ5Bp09JOFcaDVakjYQT46rf3iP3lnl_qc9xVS