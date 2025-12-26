# DNS Guidelines for Securing IoT Ecosystems

This repository contains datasets, analysis scripts, and experiment configurations used to evaluate DNS security, privacy, and operational practices across a diverse set of real-world IoT devices.

## Overview

We analyze DNS behavior in a smart home testbed comprising over 30 consumer IoT devices. Our methodology combines:
- **Passive Monitoring** of DNS queries/responses
- **Active Manipulation** of DNS responses

Key objectives include:
- Detecting security vulnerabilities (e.g., spoofing risks)
- Assessing DNS caching and retry behaviors
- Evaluating adoption of secure DNS standards (DoH, DoT, DNSSEC)

## Testbed Environment

**Devices:**  
> 30+ consumer IoT devices categorized into: Cameras, Doorbells, Smart Plugs, Hubs, Speakers, Sensors, Lights, Appliances, Health, and Pet Care.

**Examples:**
- **Cameras:** Arlo Pro 4, Blurams, Wyze Cam Pan, Google Nest Cam  
- **Smart Plugs:** Tapo P110, Meross, Belkin  
- **Speakers:** Sonos One, Bose Home 500  
- **Health:** QardioBase, Withings Sleep Analyzer  

**Infrastructure:**
- **Unbound DNS Server:** Injects crafted DNS responses to test device behavior  
- **AP Collection Server:** Multi-adapter Wi-Fi data collector  
- **DNS DoS Server:** Simulates amplification and resource-record duplication attacks  
- **Automated Power Control:** Synchronizes device restarts  

## Analysis Framework

### Passive DNS Analysis

**Scripts**
- `Analyze-DNS-Passive-Experiments.ipynb`: Analyze passive experiments. 

**Key Metrics & Plots**
- **Query & Answer Volumes:**  
  - `dns_query_counts.pdf`, `dns_answer_counts.pdf`
- **Caching Behavior:**  
  - `average_ttl_log.pdf`, `avg_time_between_queries_log.pdf`
- **Query Diversity:**  
  - `dns_query_types.pdf`, `distinct_addresses.pdf`
- **Reply Structure:**  
  - `average_answers_per_frame.pdf`
- **Protocol Features:**  
  - EDNS(0) usage, retry rates, query normalization, mDNS count

### Active DNS Experiments

**Scripts**
- `Analyze-DNS-Active-Experiments.ipynb`: Analyze active experiments.

We actively manipulate DNS responses to assess device robustness.

**TTL Manipulation**
- `Experiment_1_ttl_0`, `ttl_0_1`, `ttl_01`, `ttl_01000000000`

**Record Injection**
- `Experiment_1_A_192_0_2_1`, `CNAME_alias`, `AAAA_2001_0db8_1`

**DNS Flooding & Amplification**
- `dos_1_answer_x10_replies` to `x100`  
- `dos_1_request_1_reply_x10` to `x100`

These simulate malicious resolver behaviors and test how devices respond to altered DNS answers.

## Findings Summary

- **Security Vulnerabilities:**  
  - Predictable transaction IDs  
  - Non-randomized source ports  
  - Weak entropy leading to spoofing risks  

- **Operational Issues:**  
  - High DNS query rates  
  - Ignoring TTL values  
  - Hardcoded resolvers and erratic retry logic  

- **Lack of Modern DNS Features:**  
  - Poor support for DoH, DoT, DNSSEC across many devices  

## Citation

If you use this dataset or analysis scripts, please cite our paper: 

## License

This repository is licensed under [LICENSE_TYPE]. Scripts for analysis depend on Python, Jupyter, and Tshark.

## Dataset Access

The datasets are available at: 
---

For questions, contact us through the GitHub Issues page.
