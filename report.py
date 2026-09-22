#!/usr/bin/env python3
"""Render results.json (from compare.py) into a PDF evaluation report.

    python compare.py deepset safeguard jailbreak spml slabs password mixed --n 50 --json results.json
    python report.py results.json jev-guard-evaluation.pdf
"""

import json
import sys
from pathlib import Path
from datetime import date

from jev_guard.bench.datasets import CATEGORY

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

INK = colors.HexColor("#1a1a1a")
MUTED = colors.HexColor("#5b6472")
RULE = colors.HexColor("#d4d8de")
BAND = colors.HexColor("#f3f5f8")
WIN = colors.HexColor("#1d7a45")
LOSS = colors.HexColor("#a8341f")

DATASET_NOTES = {
    "deepset": "deepset/prompt-injections — direct injection, mixed German/English",
    "safeguard": "xTRam1/safe-guard-prompt-injection — direct injection, larger and more varied",
    "jailbreak": "jackhhao/jailbreak-classification — jailbreak vs benign",
    "spml": "reshabhs/SPML_Chatbot_Prompt_Injection — injection judged against a given system prompt",
    "slabs": "S-Labs/prompt-injection-dataset — independent direct-injection set",
    "password": "ivanleomk/prompt_injection_password — attempts to extract a withheld secret",
    "mixed": "jayavibhav/prompt-injection — large corpus, benign half is ordinary QA text",
    "jailbreakhub": "walledai/JailbreakHub — real in-the-wild prompts from prompt-sharing communities",
    "jbb": "JailbreakBench — 100 harmful and 100 deliberately matched benign",
    "gandalf": "Lakera/gandalf_ignore_instructions — real extraction attempts, all positive (recall only)",
    "bipia": "BIPIA-derived — INDIRECT injection embedded in retrieved content",
}


def styles():
    s = getSampleStyleSheet()
    s.add(ParagraphStyle("TitleBig", parent=s["Title"], fontName="Helvetica-Bold",
                         fontSize=23, leading=27, textColor=INK, alignment=TA_LEFT, spaceAfter=4))
    s.add(ParagraphStyle("Sub", parent=s["Normal"], fontSize=10.5, leading=15,
                         textColor=MUTED, spaceAfter=16))
    s.add(ParagraphStyle("H", parent=s["Heading2"], fontName="Helvetica-Bold", fontSize=13.5,
                         leading=17, textColor=INK, spaceBefore=17, spaceAfter=7))
    s.add(ParagraphStyle("H3", parent=s["Heading3"], fontName="Helvetica-Bold", fontSize=10.5,
                         leading=14, textColor=INK, spaceBefore=11, spaceAfter=4))
    s.add(ParagraphStyle("Body", parent=s["Normal"], fontSize=9.8, leading=14.5,
                         textColor=INK, spaceAfter=8))
    s.add(ParagraphStyle("Small", parent=s["Normal"], fontSize=8.3, leading=11.5, textColor=MUTED))
    s.add(ParagraphStyle("Cell", parent=s["Normal"], fontSize=8.4, leading=11, textColor=INK))
    s.add(ParagraphStyle("Mono", parent=s["Normal"], fontName="Courier", fontSize=7.6,
                         leading=10.5, textColor=INK))
    return s


def grid(data, widths, align_right=(), header=True, zebra=True):
    t = Table(data, colWidths=widths, hAlign="LEFT")
    cmds = [
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.4),
        ("TEXTCOLOR", (0, 0), (-1, -1), INK),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, RULE),
    ]
    if header:
        cmds += [
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 0), (-1, 0), BAND),
            ("LINEBELOW", (0, 0), (-1, 0), 0.9, MUTED),
        ]
    if zebra:
        for r in range(1, len(data)):
            if r % 2 == 0:
                cmds.append(("BACKGROUND", (0, r), (-1, r), colors.HexColor("#fafbfc")))
    for col in align_right:
        cmds.append(("ALIGN", (col, 0), (col, -1), "RIGHT"))
    t.setStyle(TableStyle(cmds))
    return t


def build(results: dict, out_path: str, sweep: dict | None = None, armor_cfg: dict | None = None) -> None:
    s = styles()
    doc = SimpleDocTemplate(
        out_path, pagesize=LETTER,
        leftMargin=0.78 * inch, rightMargin=0.78 * inch,
        topMargin=0.72 * inch, bottomMargin=0.72 * inch,
        title="jev-guard vs Model Armor — Prompt Injection Evaluation",
        author="jev-guard",
    )
    story = []

    total_n = sum(r["n"] for r in results.values())
    total_attacks = sum(r["attacks"] for r in results.values())
    jev_only = sum(len(r["jev_only"]) for r in results.values())
    armor_only = sum(len(r["armor_only"]) for r in results.values())
    both_missed = sum(len(r["both_missed"]) for r in results.values())
    jev_wins = sum(1 for r in results.values() if r["jev"]["f1"] > r["armor"]["f1"] + 0.005)
    ties = sum(1 for r in results.values() if abs(r["jev"]["f1"] - r["armor"]["f1"]) <= 0.005)

    story += [
        Paragraph("Prompt Injection Detection: jev-guard vs Model Armor", s["TitleBig"]),
        Paragraph(
            f"Head-to-head evaluation over {total_n} labeled cases from {len(results)} public datasets · "
            f"{date.today().isoformat()}", s["Sub"]),
    ]

    # --- summary -------------------------------------------------------------
    def pct(v):
        # Attack-only datasets have no negatives, so an FPR does not exist for them.
        return "—" if v != v else f"{v:.2f}"

    worst = min(results.items(), key=lambda kv: kv[1]["jev"]["f1"] - kv[1]["armor"]["f1"])
    high_fpr = sorted(results.items(), key=lambda kv: -(kv[1]["jev"]["fpr"] if kv[1]["jev"]["fpr"] == kv[1]["jev"]["fpr"] else -1))[:2]

    story.append(Paragraph("Summary", s["H"]))
    story.append(Paragraph(
        f"Across {total_n} labeled cases from {len(results)} public datasets, jev-guard scored a higher F1 "
        f"on <b>{jev_wins} of {len(results)}</b>. Results differ sharply by attack class, so the per-class "
        f"aggregate below is the meaningful summary rather than any single figure.", s["Body"]))
    story.append(Paragraph(
        f"The margin tracks how realistic each dataset's benign half is. Against ordinary question-answering "
        f"negatives jev-guard dominates; against real prompt-sharing traffic its precision collapses — on "
        f"<b>{worst[0]}</b> Model Armor wins outright ({worst[1]['armor']['f1']:.2f} vs "
        f"{worst[1]['jev']['f1']:.2f}) and jev-guard's false-positive rate reaches "
        f"{high_fpr[0][1]['jev']['fpr']:.2f}. A guard that flags a third of legitimate traffic is not "
        f"deployable, whatever its recall.", s["Body"]))

    head = ["Dataset", "Type", "n", "jev F1", "Model Armor F1", "jev R", "Model Armor R",
            "jev FPR", "Model Armor FPR"]
    rows = [head]
    ordered = sorted(results.items(),
                     key=lambda kv: ({"direct": 0, "jailbreak": 1, "indirect": 2}.get(CATEGORY.get(kv[0], ""), 3),
                                     -kv[1]["jev"]["f1"]))
    band_rows, current = {}, None
    for i, (name, _) in enumerate(ordered, start=1):
        cat = CATEGORY.get(name, "other")
        if cat != current:
            band_rows[i] = cat
            current = cat
    for name, r in ordered:
        rows.append([
            name, CATEGORY.get(name, "—"), str(r["n"]),
            f"{r['jev']['f1']:.2f}", f"{r['armor']['f1']:.2f}",
            f"{r['jev']['recall']:.2f}", f"{r['armor']['recall']:.2f}",
            pct(r["jev"]["fpr"]), pct(r["armor"]["fpr"]),
        ])
    t = grid(rows, [0.92 * inch, 0.66 * inch, 0.3 * inch, 0.52 * inch, 0.98 * inch,
                    0.47 * inch, 0.93 * inch, 0.56 * inch, 1.03 * inch],
             align_right=(2, 3, 4, 5, 6, 7, 8))
    extra = []
    for i, cat in band_rows.items():
        extra.append(("LINEABOVE", (0, i), (-1, i), 0.9, MUTED))
    for i, (_, r) in enumerate(ordered, start=1):
        better = WIN if r["jev"]["f1"] > r["armor"]["f1"] + 0.005 else INK
        extra.append(("TEXTCOLOR", (3, i), (3, i), better))
        extra.append(("FONTNAME", (3, i), (3, i), "Helvetica-Bold"))
    t.setStyle(TableStyle(extra))
    story += [t, Spacer(1, 6),
              Paragraph("Sorted by attack class — direct injection, then jailbreak, then indirect — with a "
                        "rule at each boundary. R is recall; FPR is the false-positive rate, shown as "
                        "“—” for datasets that contain only attacks and therefore have no negatives to "
                        "measure it against. Green marks the higher F1.", s["Small"])]

    # Per-category aggregate, which is what the comparison is actually about.
    agg = {}
    for name, r in results.items():
        cat = CATEGORY.get(name, "other")
        a = agg.setdefault(cat, {"n": 0, "jtp": 0, "jfn": 0, "atp": 0, "afn": 0, "jfp": 0, "afp": 0, "jtn": 0, "atn": 0})
        a["n"] += r["n"]
        a["jtp"] += r["jev"]["tp"]; a["jfn"] += r["jev"]["fn"]; a["jfp"] += r["jev"]["fp"]; a["jtn"] += r["jev"]["tn"]
        a["atp"] += r["armor"]["tp"]; a["afn"] += r["armor"]["fn"]; a["afp"] += r["armor"]["fp"]; a["atn"] += r["armor"]["tn"]
    crows = [["Attack class", "cases", "jev recall", "Model Armor recall", "jev FPR", "Model Armor FPR"]]
    for cat in ("direct", "jailbreak", "indirect"):
        if cat not in agg:
            continue
        a = agg[cat]
        jr = a["jtp"] / (a["jtp"] + a["jfn"]) if a["jtp"] + a["jfn"] else float("nan")
        ar = a["atp"] / (a["atp"] + a["afn"]) if a["atp"] + a["afn"] else float("nan")
        jf = a["jfp"] / (a["jfp"] + a["jtn"]) if a["jfp"] + a["jtn"] else float("nan")
        af = a["afp"] / (a["afp"] + a["atn"]) if a["afp"] + a["atn"] else float("nan")
        crows.append([cat, str(a["n"]), f"{jr:.2f}", f"{ar:.2f}", pct(jf), pct(af)])
    story += [Spacer(1, 12), Paragraph("Aggregate by attack class", s["H3"]), Spacer(1, 4),
              grid(crows, [1.05 * inch, 0.55 * inch, 0.82 * inch, 1.28 * inch, 0.7 * inch, 1.18 * inch],
                   align_right=(1, 2, 3, 4, 5))]

    # --- method --------------------------------------------------------------

    story.append(Paragraph("Where the false positives come from", s["H"]))
    story.append(Paragraph(
        "Diagnosing the flagged benign cases found two definition errors rather than threshold problems. "
        "The prompt-injection question asked whether a message contained instructions addressed to an AI — "
        "which describes prompting itself, and flagged users setting a persona. Rewritten around provenance "
        "(instructions arriving inside material the sender asked the assistant to process), its false "
        "positives on jailbreakhub fell from 87 to 11. The harmful-request question did not distinguish "
        "seeking capability from seeking understanding, and flagged questions about the history of bomb "
        "technology and about regulatory loopholes. Both fixes are in the numbers reported here.", s["Body"]))
    story.append(Paragraph(
        "The residual jailbreakhub gap is partly a labelling disagreement rather than a detection failure: "
        "much of its benign half consists of persona-override prompts (\u201cyou are now X, stay in "
        "character\u201d) that many production guards would flag by design. It is reported as a loss "
        "regardless, because picking the interpretation that flatters the system under test is how "
        "evaluations become marketing.", s["Body"]))

    story.append(Paragraph("Method", s["H"]))
    story.append(Paragraph(
        "Both systems received identical inputs, 50 cases sampled per dataset with a fixed seed. A case counts "
        "as flagged for jev-guard when its routing policy returns anything other than <i>pass</i> (block, "
        "review, or support), and for Model Armor when <font face='Courier' size='8.5'>filterMatchState</font> "
        "is <font face='Courier' size='8.5'>MATCH_FOUND</font> on any filter. Ground truth is each dataset's "
        "own label, so both systems are scored against the same key.", s["Body"]))
    story.append(Paragraph(
        "jev-guard ran on <font face='Courier' size='8.5'>~typesafe/jev-latest</font> via OpenRouter under its "
        "<i>strict</i> policy, combining a semantic hazard battery with deterministic structural detectors. "
        "Model Armor ran against the existing <font face='Courier' size='8.5'>testing-template</font> in "
        "project <font face='Courier' size='8.5'>ma-claude</font> (us-central1).", s["Body"]))

    story.append(Paragraph("Caveats that favor jev-guard", s["H3"]))
    for caveat in [
        "<b>Model Armor ran at MEDIUM_AND_ABOVE.</b> The template sets <font face='Courier' size='8.5'>"
        "piAndJailbreakFilterSettings.confidenceLevel</font> to MEDIUM_AND_ABOVE. A LOW_AND_ABOVE setting "
        "exists and would raise its recall at some cost in false positives. These numbers are not Model "
        "Armor's ceiling.",
        "<b>Model Armor's own filter version was STABLE, not LATEST.</b> The baseline template pins "
        "<font face='Courier' size='8.5'>FILTER_VERSION_ALIAS_STABLE</font>. The permutation sweep below "
        "re-runs it on LATEST.",
        "<b>SPML is structurally asymmetric.</b> Its rows pair a system prompt with a user prompt. Jev takes "
        "both as structured state; Model Armor's sanitizeUserPrompt API accepts only the user text, so it "
        "cannot see the policy being violated. That is a real capability difference, but it means the SPML "
        "gap (0.99 vs 0.55) should not be read as a like-for-like detection comparison.",
        "<b>jev-guard's policy was tuned by its author; Model Armor's template was not tuned for this test.</b> "
        "Thresholds in policy.py were iterated against deepset during development, so that dataset in "
        "particular flatters jev-guard.",
    ]:
        story.append(Paragraph(f"• {caveat}", s["Body"]))

    # --- complementarity -----------------------------------------------------
    story.append(Paragraph("Shared blind spot", s["H"]))
    story.append(Paragraph(
        f"Both systems missed {both_missed} of {total_attacks} attacks. These are the cases that matter most, "
        f"because no amount of ensembling reaches them. The recurring shape is a role-play or persona framing "
        f"that never issues an explicit override instruction:", s["Body"]))
    examples = [r for res in results.values() for r in res["both_missed"]][:6]
    for ex in examples:
        story.append(Paragraph(f"— {ex}", s["Mono"]))
        story.append(Spacer(1, 2))

    # --- per dataset ---------------------------------------------------------
    if sweep:
        story.append(Paragraph("Was the gap just configuration?", s["H"]))
        story.append(Paragraph(
            "The first round ran Model Armor on one template, which left open the objection that its settings "
            "rather than its detection explained the gap. To close that, six templates were provisioned "
            "covering every permutation of the PI filter's own axes — confidence level (LOW_AND_ABOVE / "
            "MEDIUM_AND_ABOVE / HIGH) crossed with multi-language detection on/off — all pinned to "
            "<font face='Courier' size='8.5'>FILTER_VERSION_ALIAS_LATEST</font> and isolating the "
            "prompt-injection filter (RAI, SDP and malicious-URI off) so the number measures PI detection "
            "rather than any filter firing.", s["Body"]))

        for ds, data in sweep.items():
            rows = [["Configuration", "Precision", "Recall", "F1", "FPR"]]
            j = data["jev"]
            rows.append(["jev-guard (reference)", f"{j['precision']:.2f}", f"{j['recall']:.2f}",
                         f"{j['f1']:.2f}", f"{j['fpr']:.2f}"])
            for label, m in data["armor"].items():
                rows.append([f"Model Armor {label}", f"{m['precision']:.2f}", f"{m['recall']:.2f}",
                             f"{m['f1']:.2f}", f"{m['fpr']:.2f}"])
            block = [Paragraph(f"{ds} — all PI permutations (n={data['n']})", s["H3"]), Spacer(1, 4),
                     grid(rows, [2.0 * inch, 0.8 * inch, 0.66 * inch, 0.56 * inch, 0.56 * inch],
                          align_right=(1, 2, 3, 4))]
            style = [("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold")]
            block[-1].setStyle(TableStyle(style))
            block.append(Spacer(1, 10))
            story.append(KeepTogether(block))

        story.append(Paragraph("Two results", s["H3"]))
        first = next(iter(sweep.values()))
        ladder = {k.split("/")[0]: v["recall"] for k, v in first["armor"].items() if k.endswith("ml=on")}
        ds_name = next(iter(sweep))
        story.append(Paragraph(
            f"<b>Confidence level behaves as documented but does not close the gap.</b> Recall rises "
            f"monotonically as the threshold loosens — on {ds_name} {ladder.get('high', float('nan')):.2f} "
            f"(HIGH) to {ladder.get('medium', float('nan')):.2f} (MEDIUM) to "
            f"{ladder.get('low', float('nan')):.2f} (LOW) — with precision staying at 1.00 throughout. Even "
            f"at its most sensitive setting Model Armor's PI filter reaches "
            f"{ladder.get('low', float('nan')):.2f} recall against jev-guard's "
            f"{first['jev']['recall']:.2f} on the same cases. The gap is therefore not a threshold "
            f"artifact.", s["Body"]))
        story.append(Paragraph(
            "<b>Multi-language detection had no measurable effect.</b> Across 416 cases the flag changed "
            "exactly one verdict (deepset at MEDIUM, 0.23 vs 0.22 recall — a single case out of 60 attacks, "
            "which is noise). A direct spot check on three explicit German override instructions gave "
            "identical results either way, and two of the three went undetected even at LOW_AND_ABOVE with "
            "the flag enabled. The German misses are therefore a capability gap in the prompt-injection "
            "filter rather than a configuration problem. The flag may well affect the RAI or SDP filters, "
            "which these isolated templates switch off; it does not appear to affect prompt-injection "
            "detection.", s["Body"]))

    story.append(Paragraph("Per-dataset detail", s["H"]))

    if armor_cfg:
        story.append(Paragraph("Model Armor configuration used for every dataset below", s["H3"]))
        rai = ", ".join(f"{t.replace('_', ' ').title()} {c.replace('_AND_ABOVE', '+')}" for t, c in armor_cfg["rai"])
        pi = armor_cfg["pi_and_jailbreak"]
        crows = [
            ["Setting", "Value"],
            ["Template", f"{armor_cfg['template']} ({armor_cfg['project']})"],
            ["Prompt injection / jailbreak",
             f"{pi.get('filterEnforcement', '—')}, {pi.get('confidenceLevel', '—')}"],
            ["Responsible AI filters", rai or "—"],
            ["Sensitive Data Protection", armor_cfg["sdp"]],
            ["Malicious URI", armor_cfg["malicious_uri"]],
            ["Multi-language detection", "enabled" if armor_cfg["multilang"] else "not enabled"],
            ["Filter version", armor_cfg["filter_version"]],
        ]
        story.append(grid(crows, [1.9 * inch, 4.4 * inch], header=True))
        story.append(Spacer(1, 5))
        story.append(Paragraph(
            "A case counts as flagged for Model Armor when any of these filters returns "
            "<font face='Courier' size='8.5'>MATCH_FOUND</font>, not the prompt-injection filter alone — so "
            "an SDP or Responsible AI match also counts as a detection in its favour. Note the filter "
            "version is STABLE rather than LATEST, and multi-language detection is off; the permutation "
            "sweep above varies both and finds the confidence level matters while multi-language does not.",
            s["Small"]))
        story.append(Spacer(1, 12))
    for name, r in results.items():
        block = [Paragraph(name, s["H3"]),
                 Paragraph(DATASET_NOTES.get(name, ""), s["Small"]), Spacer(1, 5)]
        rows = [["System", "Precision", "Recall", "F1", "FPR", "TP", "FP", "TN", "FN"]]
        for label, key in (("jev-guard", "jev"), ("Model Armor", "armor")):
            m = r[key]
            rows.append([label, f"{m['precision']:.2f}", f"{m['recall']:.2f}", f"{m['f1']:.2f}",
                         f"{m['fpr']:.2f}", str(m["tp"]), str(m["fp"]), str(m["tn"]), str(m["fn"])])
        block.append(grid(rows, [1.02 * inch, 0.76 * inch, 0.62 * inch, 0.5 * inch, 0.5 * inch,
                                 0.42 * inch, 0.42 * inch, 0.42 * inch, 0.42 * inch],
                          align_right=(1, 2, 3, 4, 5, 6, 7, 8)))
        block.append(Spacer(1, 4))
        block.append(Paragraph(
            f"{r['attacks']} attacks / {r['n']} cases · agreement {r['agreement']:.0%} · "
            f"jev-only {len(r['jev_only'])}, armor-only {len(r['armor_only'])}, "
            f"both missed {len(r['both_missed'])}", s["Small"]))
        block.append(Spacer(1, 11))
        story.append(KeepTogether(block))

    story.append(Paragraph("Reproducing this", s["H"]))
    story.append(Paragraph(
        "python compare.py deepset safeguard jailbreak spml slabs password mixed --n 50 --json results.json<br/>"
        "python report.py results.json jev-guard-evaluation.pdf", s["Mono"]))

    doc.build(story)


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "results.json"
    dst = sys.argv[2] if len(sys.argv) > 2 else "jev-guard-evaluation.pdf"
    sweep_path = Path(sys.argv[3] if len(sys.argv) > 3 else "sweep.json")
    sweep = json.loads(sweep_path.read_text()) if sweep_path.exists() else None
    cfg_path = Path("armor_config.json")
    armor_cfg = json.loads(cfg_path.read_text()) if cfg_path.exists() else None
    build(json.loads(open(src).read()), dst, sweep, armor_cfg)
    print(f"wrote {dst}")
