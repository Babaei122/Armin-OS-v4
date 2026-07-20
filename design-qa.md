**Design QA — Orbit brand and daily insight update**

- source visual truth paths:
  - `C:\Users\Persian NB\Documents\Codex\2026-07-18\github-plugin-github-openai-curated-remote-6\work\Armin-OS-v4\assets\brand\planos-orbit-mark.png`
  - `C:\Users\Persian NB\Documents\Codex\2026-07-18\github-plugin-github-openai-curated-remote-6\work\Armin-OS-v4\assets\brand\daily-insight-orbit-dark.png`
  - `C:\Users\Persian NB\Documents\Codex\2026-07-18\github-plugin-github-openai-curated-remote-6\work\Armin-OS-v4\assets\brand\daily-insight-orbit-mobile.png`
  - `C:\Users\Persian NB\Documents\Codex\2026-07-18\github-plugin-github-openai-curated-remote-6\work\Armin-OS-v4\assets\brand\daily-insight-orbit-mobile-dark.png`
- implementation screenshot paths:
  - `C:\Users\Persian NB\Documents\Codex\2026-07-18\github-plugin-github-openai-curated-remote-6\work\Armin-OS-v4\audit-assets\brand-insight-dark-desktop.png`
  - `C:\Users\Persian NB\Documents\Codex\2026-07-18\github-plugin-github-openai-curated-remote-6\work\Armin-OS-v4\audit-assets\brand-insight-light-mobile.png`
  - `C:\Users\Persian NB\Documents\Codex\2026-07-18\github-plugin-github-openai-curated-remote-6\work\Armin-OS-v4\audit-assets\brand-insight-dark-mobile.png`
- viewports: desktop default 1280 × 720; mobile 390 × 844 CSS pixels
- states: dashboard in light and dark themes, empty-planner baseline
- primary interactions tested: mobile theme toggle light → dark and dark → light; persistence after reload
- console errors checked: yes — no errors or warnings

**Findings**

- No actionable P0/P1/P2 mismatch remains.
- The sidebar and mobile app mark now use the same P-with-check orbital symbol as the daily insight artwork.
- Mobile no longer crops the desktop-wide banner. Dedicated portrait light and dark sources keep the mark centered in the safe upper region and reserve the lower region for live content.
- The dark theme uses a separately generated midnight artwork rather than a color filter over the light image.

**Required Fidelity Surfaces**

- Fonts and typography: IRANSansX hierarchy is preserved; mobile headline remains readable without clipping at 390px.
- Spacing and layout rhythm: the mobile hero is 327 × 500px, fully inside the viewport, with stable 18–22px internal spacing and no horizontal overflow.
- Colors and visual tokens: light pearl/sky/lavender and dark navy/cobalt palettes match their generated visual sources; overlays preserve text contrast.
- Image quality and asset fidelity: all hero and logo imagery uses generated raster assets at higher-than-display resolution. The app/PWA icons were derived from the same generated orbital artwork.
- Copy and content: existing Persian planner copy is preserved; English digits remain enforced.

**Full-view Comparison Evidence**

- Desktop dark implementation: `C:\Users\Persian NB\Documents\Codex\2026-07-18\github-plugin-github-openai-curated-remote-6\work\Armin-OS-v4\audit-assets\brand-insight-dark-desktop.png`
- Mobile light implementation: `C:\Users\Persian NB\Documents\Codex\2026-07-18\github-plugin-github-openai-curated-remote-6\work\Armin-OS-v4\audit-assets\brand-insight-light-mobile.png`
- Mobile dark implementation: `C:\Users\Persian NB\Documents\Codex\2026-07-18\github-plugin-github-openai-curated-remote-6\work\Armin-OS-v4\audit-assets\brand-insight-dark-mobile.png`

**Focused Region Comparison Evidence**

- Light source and rendered hero in one comparison image: `C:\Users\Persian NB\Documents\Codex\2026-07-18\github-plugin-github-openai-curated-remote-6\work\Armin-OS-v4\audit-assets\brand-insight-light-mobile-comparison.png`
- Dark source and rendered hero in one comparison image: `C:\Users\Persian NB\Documents\Codex\2026-07-18\github-plugin-github-openai-curated-remote-6\work\Armin-OS-v4\audit-assets\brand-insight-dark-mobile-comparison.png`

**Comparison History**

- Pass 1: the desktop-wide hero was visibly over-cropped on mobile. Added dedicated 4:5 light and dark assets and a 390px-specific layout.
- Pass 2: verified exact 327 × 500px hero bounds, centered backgrounds, no clipping, no horizontal overflow, and zero Persian/Arabic digit glyphs.
- Pass 3: compared both generated mobile sources with the rendered cards in combined images; no remaining P0/P1/P2 issue.

final result: passed
