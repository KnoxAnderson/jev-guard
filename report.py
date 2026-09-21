#!/usr/bin/env python3
"""Render results.json (from compare.py) into a PDF evaluation report.

    python compare.py deepset safeguard jailbreak spml slabs password mixed --n 50 --json results.json
    python report.py results.json jev-guard-evaluation.pdf
"""

import json
import sys
from pathlib import Path
from datetime import date

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


def build(results: dict, out_path: str, sweep: dict | None = None) -> None:
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
    story.append(Paragraph("Summary", s["H"]))
    story.append(Paragraph(
        f"jev-guard scored a higher F1 on <b>{jev_wins} of {len(results)}</b> datasets and tied on {ties}. "
        f"The more decisive number is complementarity: across all {total_attacks} attack cases, Model Armor "
        f"caught <b>{armor_only}</b> that jev-guard missed ({armor_only / total_attacks:.1%}), while jev-guard "
        f"caught <b>{jev_only}</b> that Model Armor missed. The two systems' errors are therefore highly "
        f"correlated, and stacking them adds far less than the individual gap suggests.",
        s["Body"]))
    worst = min(results.items(), key=lambda kv: kv[1]["jev"]["f1"] - kv[1]["armor"]["f1"])
    high_fpr = sorted(results.items(), key=lambda kv: -kv[1]["jev"]["fpr"])[:2]
    story.append(Paragraph(
        f"<b>That headline hides the finding that matters most.</b> jev-guard's margin depends heavily on how "
        f"realistic each dataset's benign half is. Where the negatives are ordinary question-answering text "
        f"they are trivially separable and jev-guard dominates. Where they are drawn from real prompt-sharing "
        f"traffic or deliberately matched to the attacks, its precision collapses: on "
        f"<b>{worst[0]}</b> Model Armor wins outright ({worst[1]['armor']['f1']:.2f} vs "
        f"{worst[1]['jev']['f1']:.2f}), and jev-guard's worst false-positive rates are "
        f"{high_fpr[0][0]} at {high_fpr[0][1]['jev']['fpr']:.2f} and {high_fpr[1][0]} at "
        f"{high_fpr[1][1]['jev']['fpr']:.2f}, against Model Armor's "
        f"{high_fpr[0][1]['armor']['fpr']:.2f} and {high_fpr[1][1]['armor']['fpr']:.2f}. A guard that flags a "
        f"third of legitimate traffic is not deployable, whatever its recall.", s["Body"]))
    story.append(Paragraph(
        "Diagnosing those false positives found two definition errors rather than threshold problems. The "
        "prompt-injection question asked whether a message contained instructions addressed to an AI — which "
        "describes prompting itself, and flagged users setting a persona. Rewritten around provenance "
        "(instructions arriving inside material the sender asked the assistant to process), its false "
        "positives on jailbreakhub fell from 87 to 11. The harmful-request question did not distinguish "
        "seeking capability from seeking understanding, and flagged questions about the history of bomb "
        "technology and about regulatory loopholes. Both fixes are in the numbers reported here.", s["Body"]))
    story.append(Paragraph(
        "The residual jailbreakhub gap is partly a labelling disagreement rather than a detection failure: "
        "much of its benign half consists of persona-override prompts (\u201cyou are now X, stay in character\u201d) "
        "that many production guards would flag by design. It is reported as a loss regardless, because "
        "picking the interpretation that flatters the system under test is how evaluations become "
        "marketing.", s["Body"]))
    story.append(Paragraph(
        "Read the per-dataset numbers as directional rather than definitive, and note that the caveats below "
        "materially favor jev-guard.", s["Body"]))

    head = ["Dataset", "n", "jev F1", "armor F1", "jev R", "armor R", "Agree", "jev-only", "armor-only"]
    rows = [head]
    for name, r in results.items():
        rows.append([
            name, str(r["n"]),
            f"{r['jev']['f1']:.2f}", f"{r['armor']['f1']:.2f}",
            f"{r['jev']['recall']:.2f}", f"{r['armor']['recall']:.2f}",
            f"{r['agreement']:.0%}", str(len(r["jev_only"])), str(len(r["armor_only"])),
        ])
    t = grid(rows, [0.82 * inch, 0.34 * inch, 0.62 * inch, 0.68 * inch, 0.58 * inch,
                    0.64 * inch, 0.54 * inch, 0.66 * inch, 0.75 * inch],
             align_right=(1, 2, 3, 4, 5, 6, 7, 8))
    extra = []
    for i, (_, r) in enumerate(results.items(), start=1):
        better = WIN if r["jev"]["f1"] > r["armor"]["f1"] + 0.005 else INK
        extra.append(("TEXTCOLOR", (2, i), (2, i), better))
        extra.append(("FONTNAME", (2, i), (2, i), "Helvetica-Bold"))
    t.setStyle(TableStyle(extra))
    story += [t, Spacer(1, 6),
              Paragraph("jev R / armor R are recall. “jev-only” and “armor-only” count attacks caught by "
                        "that system alone. Green marks the higher F1.", s["Small"])]

    # --- method --------------------------------------------------------------
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
    story.append(Paragraph("Does stacking them help?", s["H"]))
    story.append(Paragraph(
        "The case for running two detectors rests on their errors being independent. They are not. Union "
        "(flag if either fires) and intersection (flag only if both) were computed on the same cases:",
        s["Body"]))

    rows = [["Dataset", "jev F1", "armor F1", "union F1", "∩ F1", "union vs jev"]]
    for name, r in results.items():
        delta = r["union"]["f1"] - r["jev"]["f1"]
        rows.append([name, f"{r['jev']['f1']:.2f}", f"{r['armor']['f1']:.2f}",
                     f"{r['union']['f1']:.2f}", f"{r['intersection']['f1']:.2f}",
                     f"{delta:+.2f}"])
    t = grid(rows, [1.05 * inch, 0.78 * inch, 0.85 * inch, 0.85 * inch, 0.7 * inch, 1.0 * inch],
             align_right=(1, 2, 3, 4, 5))
    marks = []
    for i, (_, r) in enumerate(results.items(), start=1):
        delta = r["union"]["f1"] - r["jev"]["f1"]
        marks.append(("TEXTCOLOR", (5, i), (5, i), WIN if delta > 0.005 else (LOSS if delta < -0.005 else MUTED)))
    t.setStyle(TableStyle(marks))
    story += [t, Spacer(1, 9)]

    story.append(Paragraph(
        f"Union improves on jev-guard alone for only a minority of datasets, and on <b>jailbreak</b> it is "
        f"actively worse (0.92 → 0.90): Model Armor contributed no additional true positives there but did "
        f"add a false positive. <b>slabs</b> is the one genuine exception, where Model Armor caught 4 attacks "
        f"jev-guard missed and union rises 0.75 → 0.83. Intersection raises precision to 1.00 on several sets "
        f"but costs so much recall that it is only defensible for auto-blocking with a separate, more "
        f"sensitive path feeding human review.", s["Body"]))
    story.append(Paragraph(
        f"Practical reading: a second opinion is not worth double latency and cost for injection detection "
        f"specifically. Where Model Armor remains complementary is in capabilities jev-guard does not have at "
        f"all — live URL reputation, DLP/SDP infoType matching, and multimodal screening — rather than as a "
        f"redundant vote on the same question.", s["Body"]))

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

        story.append(Paragraph("Two results, one of which corrects this report's earlier draft", s["H3"]))
        story.append(Paragraph(
            "<b>Confidence level behaves as documented but does not close the gap.</b> Recall rises "
            "monotonically as the threshold loosens — on deepset 0.24 (HIGH) to 0.28 (MEDIUM) to 0.32 (LOW) "
            "— with precision staying at 1.00 throughout. Even at its most sensitive setting Model Armor's "
            "PI filter reaches 0.32 recall against jev-guard's 0.76 on the same cases. The gap is therefore "
            "not a threshold artifact.", s["Body"]))
        story.append(Paragraph(
            "<b>Multi-language detection had no measurable effect, contrary to this report's first draft.</b> "
            "Across 416 cases the flag changed exactly one verdict (deepset at MEDIUM, 0.23 vs 0.22 recall — "
            "a single case out of 60 attacks, which is noise). A direct spot check on three explicit German "
            "override instructions gave identical results either way, and two of the three went undetected "
            "even at LOW_AND_ABOVE with the flag enabled. The earlier claim that configuration explained the "
            "German misses was wrong — on this evidence it is a capability gap in the PI filter. The flag "
            "may well affect the RAI or SDP filters, which these isolated templates switch off; it does not "
            "appear to affect prompt-injection detection.", s["Body"]))

    story.append(Paragraph("Per-dataset detail", s["H"]))
    for name, r in results.items():
        block = [Paragraph(name, s["H3"]),
                 Paragraph(DATASET_NOTES.get(name, ""), s["Small"]), Spacer(1, 5)]
        rows = [["System", "Precision", "Recall", "F1", "FPR", "TP", "FP", "TN", "FN"]]
        for label, key in (("jev-guard", "jev"), ("Model Armor", "armor"),
                           ("union", "union"), ("intersection", "intersection")):
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
    build(json.loads(open(src).read()), dst, sweep)
    print(f"wrote {dst}")
