# Exploring and Enhancing Placement of Intrusion Detection Systems in RPL: A Federated Learning-Based Approach

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Institution: IIITDM Kancheepuram](https://img.shields.io/badge/Institution-IIITDM%20Kancheepuram-orange.svg)](https://www.iiitdm.ac.in/)
[![Course: CNS](https://img.shields.io/badge/Course-Computer%20Networks%20%26%20Security-green.svg)](#)
[![Team: 19](https://img.shields.io/badge/Team-19-purple.svg)](#)

This repository contains the simulation code, evaluation benchmarks, result graph generators, Beamer presentation, and IEEE Transactions LaTeX manuscript for the course project in **Computer Networks and Security (CNS)** at the **Indian Institute of Information Technology, Design and Manufacturing, Kancheepuram (IIITDM Kancheepuram)**.

### Team Members:
- **Mohammadilyas Patel** (Roll No: `CS23B1078`) — `cs23b1078@iiitdm.ac.in`
- **Shaik Sifat Ahmed** (Roll No: `CS23B1035`) — `cs23b1035@iiitdm.ac.in`
- **Abhinay** (Roll No: `CS23I1009`) — `cs23i1009@iiitdm.ac.in`

This project studies where an intrusion detection system (IDS) should be placed in an RPL sensor network. We test three placement strategies on 31,626 Cooja simulation runs, examine the FedID federated learning framework, and design a novelty extension called **Dynamic and Resilient FedID (DR-FedID)**.

---

## Key Highlights & Findings

1. **Root-Only Monitoring (CIDwL):** Monitoring only at the root node leaves downstream nodes exposed. For Blackhole attacks, detection accuracy drops by **47.3%** (falling from 98.8% at Level 1 to just 51.5% at Level 8).
2. **Monitor Scaling Overhead (CIDwG):** Covering all 10 network levels requires deploying at least 1 monitor on every level. But sending 35 features per minute from 9 nodes generates **378 KB** of raw traffic per round, which quickly congests lossy 802.15.4 channels.
3. **Voting Consensus (DCID):** Collaborative voting with a 50% majority threshold balances false alarms and detection, using just **2.7 KB** of alarm messages.
4. **Federated Learning (FedID):** Local XGBoost training with FedAvg aggregation needs **zero communication bytes during testing**. Sharing a small 10% slice of local data solves non-IID model divergence.
5. **Proposed Extension (DR-FedID):** 
   - **Dynamic Monitor Shuffling:** Rotates monitoring roles based on routing churn (+14.2% higher detection against relocating attackers).
   - **Multi-Krum Defense:** Drops poisoned updates from malicious nodes, restoring accuracy from 56.19% back to 67.96%.
   - **Local Differential Privacy (LDP):** Injects calibrated noise into sparsified weights so nodes never expose raw sample data.

---

## Architectural Comparison Matrix

| Placement Architecture | Deployment Point | Telemetry Exchange | Runtime Overhead | Data Privacy | Blackhole Detection |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CIDwL** | 6LBR (Root only) | Local capture only | **0 Bytes** | High (local) | 51.5% (downstream failure) |
| **CIDwG** | Root + Collaborators | Raw feature vectors | **378 KB / round** | None (centralized) | 99.4% (high channel load) |
| **DCID** | Collaborators + Root | Binary alarm voting | **2.7 KB / round** | Moderate | 80.5% (50% majority) |
| **FedID** | Decentralized motes | Local XGBoost weights| **0 Bytes (testing)**| High (weights only)| 95.7% (with $S=10\%$) |
| **DR-FedID (Novelty)** | Adaptive Dynamic Motes| LDP-masked updates | **0 Bytes (testing)**| Formal LDP | **98.2% (Byzantine-safe)** |

---

## Repository Structure

```text
.
├── configs/
│   └── simulation_params.yaml         # Simulation, network, and algorithm configurations
├── figures/
│   ├── fig3_detection_accuracy_heatmap.png # Detection heatmap across 7 RPL attacks
│   ├── fig4_cidwl_vs_cidwg_accuracy.png    # Spatial degradation vs distance from root
│   ├── fig5_dcid_varying_nodes_accuracy.png# Voting consensus trade-off curves
│   ├── fig6_model_divergence_data_sharing.png # Cosine similarity vs % data sharing
│   ├── fig7_fedid_vs_architectures_accuracy.png # Multi-criteria performance comparison
│   ├── novelty_architecture.png            # 3-tier DR-FedID architecture diagram
│   └── dr_fedid_simulation_results.png     # Byzantine defense & monitor shuffling plots
├── paper/
│   ├── main.tex                       # Complete IEEEtran LaTeX paper manuscript
│   ├── references.bib                 # BibTeX bibliography with full citations
│   ├── IEEEtran.cls                   # IEEE Transactions LaTeX class file
│   ├── IEEEtran.bst                   # IEEE Transactions BibTeX style file
│   ├── README.IEEEtran                # IEEEtran documentation
│   ├── Final_Paper_Report.pdf         # Compiled 5-page IEEE Transactions paper PDF
│   └── images/                        # High-resolution figures referenced in LaTeX
├── src/
│   ├── simulate_dr_fedid.py           # Simulation of Byzantine attacks & dynamic shuffling
│   ├── evaluate_architectures.py      # Benchmark evaluation of CIDwL, CIDwG, DCID, FedID
│   └── generate_result_graphs.py      # Publication-quality plotting routines
├── scripts/                           # Duplicate helper scripts matching paper paths
├── LICENSE                            # MIT License
├── requirements.txt                   # Python environment dependencies
└── README.md                          # Repository documentation
```

---

## Quickstart & Reproduction

### 1. Environment Setup

Clone the repository and install dependencies in a clean virtual environment:

```bash
git clone https://github.com/mdilyas-27/cns_project_team_19.git
cd cns_project_team_19

python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux / macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Run the Placement Evaluation Benchmark

To inspect the empirical metrics across CIDwL, CIDwG, DCID, and FedID:

```bash
python src/evaluate_architectures.py
```

### 3. Run the DR-FedID Novelty Simulation

To execute the Byzantine poisoning attack, Multi-Krum defense aggregation, and dynamic monitor shuffling simulation:

```bash
python src/simulate_dr_fedid.py
```

### 4. Re-generate All Result Figures

To re-create all publication-quality result plots (saved to `figures/`):

```bash
python src/generate_result_graphs.py
```

---

## Compiling the Research Paper (Overleaf / Local LaTeX)

The complete LaTeX paper is located in `paper/`. To compile locally:

```bash
cd paper
pdflatex main
bibtex main
pdflatex main
pdflatex main
```

Alternatively, upload `Research_Paper_Project.zip` directly to [Overleaf](https://www.overleaf.com), which compiles out-of-the-box using the included `IEEEtran.cls` and `IEEEtran.bst`.

---

## Citation & Authorship

```bibtex
@article{cns_rpl_fedid_team19,
  author    = {Mohammadilyas Patel and Shaik Sifat Ahmed and Abhinay},
  title     = {Exploring and Enhancing Placement of Intrusion Detection Systems in RPL: A Federated Learning-Based Approach},
  institution = {Indian Institute of Information Technology, Design and Manufacturing, Kancheepuram (IIITDM Kancheepuram)},
  address   = {Chennai 600127, India},
  note      = {Course: Computer Networks and Security (CNS), Team 19},
  year      = {2026},
  url       = {https://github.com/mdilyas-27/cns_project_team_19}
}
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

