"""
Shared figure style for the manuscript.

One place sets typography, sizing and colour for every figure, so that notation
and appearance are consistent across the diagrams and the result plots, and so
that a change to the target journal's column width is a one-line change here.

Sizing follows Elsevier's raster/vector guidance: single-column figures are
90 mm wide, 1.5-column 140 mm, double-column 190 mm.  Every figure is written
twice — PDF for the manuscript (vector, no resampling) and PNG at 400 dpi for
previews and for reviewers who cannot open vector files.
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

MM = 1.0 / 25.4
COL1 = 90 * MM          # single column
COL15 = 140 * MM        # 1.5 column
COL2 = 190 * MM         # double column

OUT_DIR = Path("paper/figures")

# Restrained, print-safe palette. The three configurations are ordered light to
# dark so the figures stay readable in greyscale, which reviewers print.
C_B0 = "#B4B4B4"
C_B1 = "#6E8FB2"
C_P = "#1F3B57"
C_ACCENT = "#B5522F"    # the one warm colour, reserved for "this is the finding"
C_ACCENT2 = "#7B8B45"
C_RULE = "#4C4C4C"
C_LIGHT = "#EDEDED"
C_MID = "#CFCFCF"

CONFIG_COLOR = {"B0": C_B0, "B1": C_B1, "P": C_P}

# Component fill colours for the architecture / flow diagrams, kept pale so
# black text sits on them legibly.
C_BOX_IDP = "#E4EBF2"
C_BOX_PEP = "#DCE6EE"
C_BOX_PDP = "#EDE6DE"
C_BOX_RS = "#E6EBDF"
C_BOX_ADV = "#F3E3DE"


def apply_style() -> None:
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["DejaVu Serif", "Times New Roman", "Nimbus Roman"],
        "mathtext.fontset": "dejavuserif",
        "font.size": 7.5,
        "axes.titlesize": 8.0,
        "axes.labelsize": 7.5,
        "xtick.labelsize": 7.0,
        "ytick.labelsize": 7.0,
        "legend.fontsize": 6.8,
        "legend.frameon": False,
        "axes.linewidth": 0.6,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "xtick.major.width": 0.6,
        "ytick.major.width": 0.6,
        "xtick.major.size": 2.5,
        "ytick.major.size": 2.5,
        "lines.linewidth": 1.0,
        "lines.markersize": 3.0,
        "grid.linewidth": 0.4,
        "grid.color": "#CCCCCC",
        "figure.dpi": 130,
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.02,
        "pdf.fonttype": 42,     # embed TrueType, not Type 3 — required by many venues
        "ps.fonttype": 42,
    })


def save(fig, stem: str) -> None:
    """Write one figure as vector PDF and 400 dpi PNG."""
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT_DIR / f"{stem}.pdf")
    fig.savefig(OUT_DIR / f"{stem}.png", dpi=400)
    plt.close(fig)
    print(f"[OK] {stem}.pdf / .png")


def box(ax, x, y, w, h, text="", fc=C_LIGHT, ec=C_RULE, lw=0.7, fontsize=6.8,
        weight="normal", style="round,pad=0", ha="center", zorder=3,
        text_color="black", pad=0.010):
    """
    A labelled rounded box occupying exactly the rectangle (x, y, w, h).

    The box style carries no padding, so the rectangle a caller computes is the
    rectangle drawn; padding outside the given rect is how diagrams silently
    start overlapping once the layout is computed rather than hand-placed.
    """
    from matplotlib.patches import FancyBboxPatch
    patch = FancyBboxPatch((x, y), w, h, boxstyle=style, linewidth=lw,
                           facecolor=fc, edgecolor=ec, zorder=zorder)
    ax.add_patch(patch)
    if text:
        tx = x + w / 2 if ha == "center" else x + pad
        ax.text(tx, y + h / 2, text, ha=ha, va="center", fontsize=fontsize,
                weight=weight, zorder=zorder + 1, color=text_color,
                linespacing=1.35)
    return patch


def titled_box(ax, x, y, w, h, title, detail, fc=C_LIGHT, ec=C_RULE,
               title_size=6.6, detail_size=6.0, pad=0.012, lw=0.7,
               title_color="black", zorder=3, anchor="center", gap=0.018):
    """
    A box with a bold title line and a detail block beneath it, laid out from
    the box's own geometry so that changing the box height cannot orphan the
    text outside it.
    """
    box(ax, x, y, w, h, fc=fc, ec=ec, lw=lw, zorder=zorder)
    n = detail.count("\n") + 1 if detail else 0
    if anchor == "top":
        # Title flush to the top edge, detail hanging beneath it. Used where the
        # detail block is tall enough that a centred layout would run the two
        # into each other.
        title_y = y + h - gap
        ax.text(x + pad, title_y, title, ha="left", va="top",
                fontsize=title_size, weight="bold", zorder=zorder + 1,
                color=title_color)
        if detail:
            ax.text(x + pad, title_y - gap * 1.9, detail, ha="left", va="top",
                    fontsize=detail_size, zorder=zorder + 1, linespacing=1.34)
        return
    title_y = y + h - 0.30 * h if n <= 1 else y + h - 0.22 * h
    ax.text(x + pad, title_y, title, ha="left", va="center",
            fontsize=title_size, weight="bold", zorder=zorder + 1,
            color=title_color)
    if detail:
        ax.text(x + pad, y + 0.40 * h if n <= 1 else y + 0.36 * h, detail,
                ha="left", va="center", fontsize=detail_size, zorder=zorder + 1,
                linespacing=1.32)


def stack(y_top, y_bottom, weights, gap):
    """
    Split a vertical band into boxes with the given relative heights and a
    constant gap, returning (y, h) for each. Diagrams use this instead of
    literal coordinates so a box can never be placed on top of another one.
    """
    total = y_top - y_bottom - gap * (len(weights) - 1)
    unit = total / sum(weights)
    out = []
    y = y_top
    for wgt in weights:
        h = unit * wgt
        y -= h
        out.append((y, h))
        y -= gap
    return out


def arrow(ax, xy_from, xy_to, style="-|>", color=C_RULE, lw=0.7, ls="-",
          rad=0.0, zorder=2, mutation=6):
    from matplotlib.patches import FancyArrowPatch
    a = FancyArrowPatch(xy_from, xy_to, arrowstyle=style, color=color,
                        linewidth=lw, linestyle=ls, zorder=zorder,
                        mutation_scale=mutation,
                        connectionstyle=f"arc3,rad={rad}",
                        shrinkA=1.0, shrinkB=1.0)
    ax.add_patch(a)
    return a


def blank_axes(fig, rect=(0, 0, 1, 1)):
    ax = fig.add_axes(rect)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    return ax
