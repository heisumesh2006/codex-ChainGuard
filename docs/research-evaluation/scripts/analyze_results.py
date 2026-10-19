"""Recalculate every reported metric and figure from completed raw CSVs."""
from collections import defaultdict, Counter
import csv
import json
from pathlib import Path
import statistics as st
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BASE = Path(__file__).resolve().parents[1]
RAW, FIG = BASE / "raw", BASE / "figures"


def read(name):
    with (RAW / name).open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write(name, rows):
    with (RAW / name).open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)


def save(fig, name):
    fig.tight_layout()
    for extension in ("svg", "pdf", "png"):
        fig.savefig(FIG / (name + "." + extension), dpi=300, bbox_inches="tight")
    plt.close(fig)


def grouped(rows, keys):
    groups = defaultdict(list)
    for row in rows: groups[tuple(row[k] for k in keys)].append(row)
    return groups


def main():
    FIG.mkdir(exist_ok=True)
    plt.rcParams.update({"font.size": 10, "axes.grid": True, "grid.alpha": .22,
                         "svg.fonttype": "none", "pdf.fonttype": 42})
    for exp in (1, 2, 3):
        manifest = json.loads((RAW / f"experiment{exp}_manifest.json").read_text())
        if manifest["status"] != "COMPLETE": raise RuntimeError(f"Experiment {exp} incomplete")
    e1, attacks = read("experiment1_summary.csv"), read("experiment1_tampering.csv")
    aggregate = []
    metrics = ("recording_average_ms", "recording_median_ms", "recording_p95_ms", "auth_average_ms",
               "local_audit_average_ms", "verification_ms", "storage_bytes", "processing_ms", "gas_used",
               "gas_fee_wei", "audit_transactions", "deployment_gas_used", "workload_wall_ms")
    for (version, workload), rows in grouped(e1, ("version", "workload")).items():
        result = {"version": version, "workload": int(workload), "trials": len(rows)}
        for metric in metrics:
            values = [float(r[metric]) for r in rows]
            result.update({metric + "_mean": st.mean(values), metric + "_min": min(values), metric + "_max": max(values)})
        aggregate.append(result)
    aggregate.sort(key=lambda r: (r["version"], r["workload"]))
    write("aggregated_experiment1.csv", aggregate)
    fig, axes = plt.subplots(2, 2, figsize=(10, 7))
    for ax, metric, title, units, scale in zip(axes.flat,
            ("recording_average_ms", "recording_p95_ms", "verification_ms", "storage_bytes"),
            ("Event recording (mean)", "Event recording (p95)", "Complete audit verification", "Durable audit storage"),
            ("Time (ms)", "Time (ms)", "Time (ms)", "Size (KiB)"), (1, 1, 1, 1024)):
        for version, label, marker in (("merkle_blockchain", "Merkle + local EVM", "o"), ("hash_chain", "Hash chain", "s")):
            rows = [r for r in aggregate if r["version"] == version]
            means = [r[metric+"_mean"]/scale for r in rows]
            error = [[(r[metric+"_mean"]-r[metric+"_min"])/scale for r in rows],
                     [(r[metric+"_max"]-r[metric+"_mean"])/scale for r in rows]]
            ax.errorbar([r["workload"] for r in rows], means, yerr=error, label=label, marker=marker, capsize=3)
        ax.set(xlabel="Records", ylabel=units, title=title)
        ax.set_xscale("log"); ax.set_xticks((10,100,500,1000), labels=("10","100","500","1000"))
        ax.legend(fontsize=8)
    fig.suptitle("Local controlled audit comparison; 3 trials, bars = observed min/max", fontsize=11)
    save(fig, "experiment1_performance")
    detection = []
    for (version, policy), rows in grouped(attacks, ("version", "checkpoint_policy")).items():
        detection.append(dict(version=version, policy=policy, attempts=len(rows), detected=sum(int(r["detected"]) for r in rows)))
    write("aggregated_tampering.csv", detection)
    fig, ax = plt.subplots(figsize=(8, 4))
    labels = [r["version"].replace("merkle_blockchain","Merkle + EVM").replace("hash_chain","Hash chain")+"\n"+r["policy"].replace("_"," ") for r in detection]
    bars = ax.bar(labels, [100*r["detected"]/r["attempts"] for r in detection], color=["#185f9b","#185f9b","#cc7a00","#cc7a00"])
    for bar, row in zip(bars,detection): ax.text(bar.get_x()+bar.get_width()/2,bar.get_height()+2,f'{row["detected"]}/{row["attempts"]}',ha="center")
    ax.set(ylabel="Tampering cases detected (%)", ylim=(0,115), title="Storage rewrite attacker: external checkpoint is the trust boundary")
    ax.tick_params(axis="x", labelsize=8); save(fig,"experiment1_tampering")
    e2, independent = read("experiment2_depths.csv"), read("experiment2_independent_paths.csv")
    delegation = []
    for (version, depth), rows in grouped(e2, ("version", "depth")).items():
        delegation.append(dict(version=version, depth=int(depth), trials=len(rows),
            downstream_checks=sum(int(r["expected_downstream_invalidated"]) for r in rows),
            invalidated=sum(int(r["downstream_invalidated"]) for r in rows),
            incorrectly_retained=sum(int(r["incorrectly_retained"]) for r in rows),
            incorrectly_revoked=sum(int(r["incorrectly_revoked"]) for r in rows),
            revocation_mean_ms=st.mean(float(r["revocation_ms"]) for r in rows),
            revocation_min_ms=min(float(r["revocation_ms"]) for r in rows),
            revocation_max_ms=max(float(r["revocation_ms"]) for r in rows),
            tracing_mean_ms=st.mean(float(r["trace_average_ms"]) for r in rows)))
    delegation.sort(key=lambda r:(r["version"],r["depth"]))
    write("aggregated_experiment2.csv", delegation)
    fig, axes = plt.subplots(1, 3, figsize=(12, 3.7))
    for version, label, marker in (("original_flat","Original flat permissions","s"),("corrected_cascade","Corrected signed ancestry","o")):
        rows=[r for r in delegation if r["version"]==version]
        for ax,metric,title,unit in zip(axes,("incorrectly_retained","revocation_mean_ms","tracing_mean_ms"),
                                      ("Downstream incorrectly retained","Revocation processing","Authority check / tracing"),
                                      ("Mean count per trial","Time (ms)","Time (ms)")):
            values=[r[metric]/r["trials"] if metric=="incorrectly_retained" else r[metric] for r in rows]
            ax.plot([r["depth"] for r in rows], values, marker=marker, label=label)
            ax.set(xlabel="Root-to-leaf grant depth",ylabel=unit,title=title,xticks=(1,2,3,4))
        axes[-1].set_yscale("log")
    axes[0].legend(fontsize=7); save(fig,"experiment2_revocation")
    e3 = read("experiment3_requests.csv")
    legitimate=[r for r in e3 if r["classification"]=="legitimate"]
    malicious=[r for r in e3 if r["classification"]=="attack"]
    anomaly=[r for r in e3 if r["classification"]=="behavioral_anomaly"]
    tp=sum(r["actual"]=="BLOCK" for r in malicious); fn=len(malicious)-tp
    fp=sum(r["actual"]!="ALLOW" for r in legitimate); tn=len(legitimate)-fp
    precision=tp/(tp+fp) if tp+fp else None; recall=tp/(tp+fn) if tp+fn else None
    f1=2*precision*recall/(precision+recall) if precision is not None and recall is not None and precision+recall else None
    security=dict(total_requests=len(e3), legitimate=len(legitimate), legitimate_correctly_allowed=tn,
                  legitimate_incorrectly_blocked=fp, attacks=len(malicious), attacks_blocked=tp, attacks_allowed=fn,
                  attack_blocking_rate=recall, false_rejection_rate=fp/len(legitimate), precision=precision, recall=recall, f1=f1,
                  anomaly_requests=len(anomaly), anomalies_reviewed=sum(r["actual"]=="REVIEW" for r in anomaly),
                  latency_mean_ms=st.mean(float(r["authorization_latency_ms"]) for r in e3),
                  latency_median_ms=st.median(float(r["authorization_latency_ms"]) for r in e3))
    case_rows=[]
    for (case,),rows in grouped(e3,("case",)).items():
        case_rows.append(dict(case=case,requests=len(rows),expected=rows[0]["expected"],
                              allowed=sum(r["actual"]=="ALLOW" for r in rows),blocked=sum(r["actual"]=="BLOCK" for r in rows),
                              reviewed=sum(r["actual"]=="REVIEW" for r in rows),
                              latency_mean_ms=st.mean(float(r["authorization_latency_ms"]) for r in rows)))
    write("aggregated_experiment3.csv",case_rows)
    fig, ax=plt.subplots(figsize=(9,6))
    for category,color in (("allowed","#24834b"),("blocked","#bb4141"),("reviewed","#c48a16")):
        left=[sum(r[k] for k in ("allowed","blocked","reviewed")[:("allowed","blocked","reviewed").index(category)]) for r in case_rows]
        ax.barh(range(len(case_rows)),[r[category] for r in case_rows],left=left,label=category.title(),color=color)
    ax.set_yticks(range(len(case_rows)),labels=[r["case"].replace("_"," ") for r in case_rows])
    ax.invert_yaxis(); ax.set(xlabel="Requests (10 repetitions per case)",title="Controlled authorization security matrix")
    ax.legend(loc="upper center", bbox_to_anchor=(.5,-.17), ncol=3); save(fig,"experiment3_security_matrix")
    before=read("experiment3_before_after.csv")
    summary=dict(experiment1_trials=len(e1), experiment1_recorded_events=sum(int(r["workload"]) for r in e1),
                 experiment1_tampering=detection, experiment1_untampered_false_positives=sum(int(r["untampered_false_positives"]) for r in e1),
                 experiment2_trials=len(e2), experiment2_independent_path_cases=len(independent),
                 experiment2_independent_incorrect_revocations=sum(int(r["incorrectly_revoked"]) for r in independent),
                 experiment2=delegation,experiment3=security,
                 root_spoof_before_allowed=sum(r["actual"]=="ALLOW" for r in before if r["version"]=="original_flat"),
                 root_spoof_after_allowed=sum(r["actual"]=="ALLOW" for r in before if r["version"]=="corrected_signed"))
    (BASE/"results_summary.json").write_text(json.dumps(summary,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(summary,indent=2))


if __name__=="__main__": main()
