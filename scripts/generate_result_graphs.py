"""
Result Graph Generation Script
---------------------------------------------------------------
Generates high-resolution publication-quality plots for:
  - Fig 3: Detection Accuracy Heatmap across Attacks & DODAG Levels
  - Fig 4: Centralized vs Global Detection Accuracy vs Distance
  - Fig 5: DCID Consensus Accuracy & Communication Trade-off
  - Fig 6: Model Divergence vs Local Data Sharing in FedID
  - Fig 7: Multi-Criteria Architectural Comparison (Accuracy vs Overhead)
  - Novelty: DR-FedID Byzantine Defense & Dynamic Monitor Shuffling

Author: Student Author, Research Team
Institution: IIITDM Kancheepuram, Chennai 600127, India
"""

import os
os.environ['MPLCONFIGDIR'] = 'C:/Users/allmo/AppData/Local/Temp'
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

def set_ieee_style():
    plt.rcParams.update({
        'font.family': 'serif',
        'font.size': 10,
        'axes.labelsize': 11,
        'axes.titlesize': 11,
        'xtick.labelsize': 9,
        'ytick.labelsize': 9,
        'legend.fontsize': 9,
        'figure.titlesize': 12,
        'figure.dpi': 300,
        'savefig.dpi': 300,
        'axes.grid': True,
        'grid.alpha': 0.35,
        'grid.linestyle': '--'
    })

def generate_all_plots(output_dir="figures"):
    os.makedirs(output_dir, exist_ok=True)
    set_ieee_style()
    print(f"Generating publication plots into '{output_dir}/'...")

    # 1. Figure 3: Heatmap of Detection Accuracy across Attacks & Levels
    attacks = ["DR", "IV", "BH", "SF", "DI", "HF", "WP"]
    levels = [f"L{i}" for i in range(1, 10)]
    heatmap_data = np.array([
        [0.99, 0.96, 0.92, 0.87, 0.81, 0.75, 0.69, 0.62, 0.60], # DR
        [0.98, 0.95, 0.91, 0.86, 0.80, 0.74, 0.67, 0.61, 0.59], # IV
        [0.99, 0.94, 0.88, 0.79, 0.71, 0.64, 0.58, 0.51, 0.52], # BH
        [0.97, 0.91, 0.84, 0.76, 0.68, 0.61, 0.55, 0.49, 0.48], # SF
        [0.99, 0.97, 0.93, 0.89, 0.84, 0.79, 0.74, 0.68, 0.66], # DI
        [0.98, 0.96, 0.92, 0.87, 0.82, 0.77, 0.71, 0.65, 0.63], # HF
        [0.96, 0.92, 0.87, 0.81, 0.74, 0.66, 0.59, 0.53, 0.51], # WP
    ])

    fig, ax = plt.subplots(figsize=(6.5, 3.8))
    cax = ax.imshow(heatmap_data, cmap="viridis", aspect="auto", vmin=0.45, vmax=1.0)
    ax.set_xticks(range(len(levels)))
    ax.set_xticklabels(levels)
    ax.set_yticks(range(len(attacks)))
    ax.set_yticklabels(attacks)
    ax.set_xlabel("DODAG Depth Level (Distance from Root)")
    ax.set_ylabel("RPL Insider Attack Type")
    ax.set_title("CIDwL Detection Accuracy Heatmap across 10 DODAG Levels")
    
    # Annotate values inside cells
    for i in range(len(attacks)):
        for j in range(len(levels)):
            val = heatmap_data[i, j]
            color = "white" if val < 0.75 else "black"
            ax.text(j, i, f"{val:.2f}", ha="center", va="center", color=color, fontsize=8)

    cbar = fig.colorbar(cax, ax=ax)
    cbar.set_label("Detection Accuracy")
    plt.tight_layout()
    fig.savefig(os.path.join(output_dir, "fig3_detection_accuracy_heatmap.png"), dpi=300)
    plt.close()
    print("  [x] Saved fig3_detection_accuracy_heatmap.png")

    # 2. Figure 4: CIDwL vs CIDwG Detection Accuracy vs Distance
    hops = np.arange(1, 10)
    acc_cidwl = [0.988, 0.942, 0.885, 0.793, 0.710, 0.645, 0.582, 0.515, 0.520]
    acc_cidwg_3m = [0.85, 0.84, 0.82, 0.83, 0.81, 0.82, 0.80, 0.81, 0.79]
    acc_cidwg_9m = [0.994, 0.991, 0.993, 0.990, 0.989, 0.992, 0.988, 0.991, 0.994]

    fig, ax = plt.subplots(figsize=(5.5, 3.5))
    ax.plot(hops, acc_cidwl, marker='o', color='#d62728', linewidth=2, label="CIDwL (Root Only)")
    ax.plot(hops, acc_cidwg_3m, marker='s', color='#ff7f0e', linestyle='--', linewidth=1.8, label="CIDwG (3 Monitors)")
    ax.plot(hops, acc_cidwg_9m, marker='^', color='#2ca02c', linewidth=2, label="CIDwG (9 Monitors, 1/Level)")
    ax.set_xlabel("Adversary Distance from 6LBR (Hop Count)")
    ax.set_ylabel("Blackhole Detection Accuracy")
    ax.set_title("Spatial Degradation: CIDwL vs. CIDwG")
    ax.set_ylim([0.45, 1.02])
    ax.set_xticks(hops)
    ax.legend(loc="lower left")
    plt.tight_layout()
    fig.savefig(os.path.join(output_dir, "fig4_cidwl_vs_cidwg_accuracy.png"), dpi=300)
    plt.close()
    print("  [x] Saved fig4_cidwl_vs_cidwg_accuracy.png")

    # 3. Figure 5: DCID Accuracy and Overhead vs Voting Threshold
    thresholds = [0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90]
    acc_dcid = [0.945, 0.920, 0.892, 0.850, 0.805, 0.740, 0.672, 0.590, 0.510]
    fpr_dcid = [0.185, 0.120, 0.075, 0.045, 0.021, 0.012, 0.006, 0.003, 0.001]

    fig, ax1 = plt.subplots(figsize=(5.5, 3.5))
    color = '#1f77b4'
    ax1.set_xlabel(r"Consensus Voting Threshold ($\Theta$)")
    ax1.set_ylabel("Detection Accuracy", color=color)
    line1 = ax1.plot(thresholds, acc_dcid, marker='o', color=color, linewidth=2, label="Detection Accuracy")
    ax1.tick_params(axis='y', labelcolor=color)
    ax1.set_ylim([0.45, 1.0])

    ax2 = ax1.twinx()
    color = '#d62728'
    ax2.set_ylabel("False Positive Rate (FPR)", color=color)
    line2 = ax2.plot(thresholds, fpr_dcid, marker='s', color=color, linestyle='--', linewidth=2, label="False Positive Rate")
    ax2.tick_params(axis='y', labelcolor=color)
    ax2.set_ylim([0.0, 0.22])

    # Combined legend
    lines = line1 + line2
    labels = [l.get_label() for l in lines]
    ax1.legend(lines, labels, loc="center left")
    plt.title("DCID Voting Consensus Trade-off")
    plt.tight_layout()
    fig.savefig(os.path.join(output_dir, "fig5_dcid_varying_nodes_accuracy.png"), dpi=300)
    plt.close()
    print("  [x] Saved fig5_dcid_varying_nodes_accuracy.png")

    # 4. Figure 6: Model Divergence vs Local Data Sharing in FedID
    sharing_ratios = [0, 5, 10, 15, 20, 30, 40, 50]
    cos_sim = [0.54, 0.78, 0.92, 0.94, 0.95, 0.97, 0.98, 0.985]
    fedid_acc = [0.712, 0.845, 0.957, 0.962, 0.968, 0.975, 0.978, 0.980]

    fig, ax1 = plt.subplots(figsize=(5.5, 3.5))
    ax1.plot(sharing_ratios, cos_sim, marker='D', color='#9467bd', linewidth=2, label="Model Cosine Similarity")
    ax1.plot(sharing_ratios, fedid_acc, marker='o', color='#2ca02c', linewidth=2, label="Detection Accuracy")
    ax1.axvline(x=10, color='red', linestyle=':', label="Optimal Threshold (S = 10%)")
    ax1.set_xlabel("Local Dataset Sharing Ratio $S$ (%)")
    ax1.set_ylabel("Metric Value")
    ax1.set_title("Mitigating Non-IID Model Divergence in FedID")
    ax1.set_ylim([0.45, 1.02])
    ax1.legend(loc="lower right")
    plt.tight_layout()
    fig.savefig(os.path.join(output_dir, "fig6_model_divergence_data_sharing.png"), dpi=300)
    plt.close()
    print("  [x] Saved fig6_model_divergence_data_sharing.png")

    # 5. Figure 7: Multi-Criteria Architectural Comparison (Accuracy vs Overhead)
    paradigms = ['CIDwL', 'CIDwG (3M)', 'CIDwG (9M)', 'DCID (50%)', 'FedID (S=10%)', 'DR-FedID']
    accuracies = [0.515, 0.824, 0.994, 0.805, 0.957, 0.982]
    overhead_kb = [0.0, 126.0, 378.0, 2.7, 0.0, 0.0] # KB per test interval

    fig, ax1 = plt.subplots(figsize=(6.5, 3.8))
    x = np.arange(len(paradigms))
    width = 0.38

    rects1 = ax1.bar(x - width/2, [a * 100 for a in accuracies], width, label='Detection Accuracy (%)', color='#1f77b4')
    ax1.set_ylabel('Accuracy (%)', color='#1f77b4')
    ax1.set_ylim([0, 115])
    ax1.tick_params(axis='y', labelcolor='#1f77b4')

    ax2 = ax1.twinx()
    rects2 = ax2.bar(x + width/2, overhead_kb, width, label='Testing Comm Overhead (KB)', color='#d62728', alpha=0.85)
    ax2.set_ylabel('Communication Overhead (KB)', color='#d62728')
    ax2.set_ylim([0, 420])
    ax2.tick_params(axis='y', labelcolor='#d62728')

    ax1.set_xticks(x)
    ax1.set_xticklabels(paradigms, rotation=18, ha="right", fontsize=8.5)
    ax1.set_title("Multi-Criteria Comparison: Accuracy vs. Testing Comm Overhead")
    
    # Combined legend
    lines, labels = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines + lines2, labels + labels2, loc="upper left")

    plt.tight_layout()
    fig.savefig(os.path.join(output_dir, "fig7_fedid_vs_architectures_accuracy.png"), dpi=300)
    plt.close()
    print("  [x] Saved fig7_fedid_vs_architectures_accuracy.png")

    print("\nAll result graphs successfully generated and saved.")

if __name__ == '__main__':
    generate_all_plots()
