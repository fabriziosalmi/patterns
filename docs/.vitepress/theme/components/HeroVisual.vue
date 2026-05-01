<script setup lang="ts">
// Deterministic pseudo-random sequence so SSR and client agree.
function lcg(seed: number) {
    let n = seed
    return () => {
        n = (n * 1103515245 + 12345) % 2147483648
        return n / 2147483648
    }
}

type Seg = { x: number; w: number; blocked: boolean }

function buildTrack(seed: number): Seg[] {
    const r = lcg(seed)
    const segs: Seg[] = []
    let x = 0
    const widths = [4, 6, 8, 10, 14, 18, 22]
    const gaps = [4, 5, 6, 8, 10]
    while (x < 480) {
        const w = widths[Math.floor(r() * widths.length)]
        const gap = gaps[Math.floor(r() * gaps.length)]
        const blocked = r() < 0.07 // ~7%
        segs.push({ x, w, blocked })
        x += w + gap
    }
    return segs
}

const trackCount = 11
const tracks = Array.from({ length: trackCount }, (_, i) => ({
    y: 18 + i * 26,
    delay: -(i * 2.7),
    duration: 36 + (i % 3) * 6, // slight variance per track
    segs: buildTrack(i + 7)
}))
</script>

<template>
    <div class="hero-visual" aria-hidden="true">
        <div class="hero-visual-frame">
            <div class="hero-visual-meta">
                <span class="meta-label">// inbound · request inspection</span>
                <span class="meta-live">
                    <span class="live-dot" />
                    live
                </span>
            </div>

            <svg
                class="hero-visual-svg"
                viewBox="0 0 480 320"
                preserveAspectRatio="xMidYMid slice"
            >
                <defs>
                    <linearGradient id="edge-fade" x1="0" x2="1" y1="0" y2="0">
                        <stop offset="0" stop-color="#fff" stop-opacity="0" />
                        <stop offset="0.08" stop-color="#fff" stop-opacity="1" />
                        <stop offset="0.92" stop-color="#fff" stop-opacity="1" />
                        <stop offset="1" stop-color="#fff" stop-opacity="0" />
                    </linearGradient>
                    <mask id="edge-mask">
                        <rect x="0" y="0" width="480" height="320" fill="url(#edge-fade)" />
                    </mask>
                </defs>

                <g mask="url(#edge-mask)">
                    <g
                        v-for="(t, i) in tracks"
                        :key="i"
                        :transform="`translate(0, ${t.y})`"
                    >
                        <g
                            class="drift"
                            :style="{
                                '--drift-delay': `${t.delay}s`,
                                '--drift-duration': `${t.duration}s`
                            }"
                        >
                            <!-- two copies side-by-side give a seamless loop -->
                            <g v-for="copy in 2" :key="copy" :transform="`translate(${(copy - 1) * 480}, 0)`">
                                <template v-for="(s, j) in t.segs" :key="j">
                                    <rect
                                        :x="s.x"
                                        y="-2"
                                        :width="s.w"
                                        height="4"
                                        rx="2"
                                        :class="s.blocked ? 'seg-blocked' : 'seg-normal'"
                                    />
                                </template>
                            </g>
                        </g>
                    </g>
                </g>
            </svg>

            <div class="hero-visual-foot">
                <span class="foot-stat">
                    <span class="stat-num">99.93<span class="stat-unit">%</span></span>
                    <span class="stat-key">pass</span>
                </span>
                <span class="foot-sep" />
                <span class="foot-stat foot-stat--blocked">
                    <span class="stat-num">0.07<span class="stat-unit">%</span></span>
                    <span class="stat-key">blocked</span>
                </span>
            </div>
        </div>
    </div>
</template>

<style scoped>
.hero-visual {
    position: relative;
    width: 100%;
    max-width: 540px;
    margin-left: auto;
}

.hero-visual-frame {
    position: relative;
    border-radius: 18px;
    border: 1px solid var(--vp-c-divider);
    background:
        linear-gradient(180deg, var(--vp-c-bg-elv), var(--vp-c-bg-alt));
    padding: 18px 18px 14px;
    box-shadow:
        0 1px 0 rgba(255, 255, 255, 0.04) inset,
        0 24px 60px -28px rgba(0, 0, 0, 0.18);
    overflow: hidden;
}

.dark .hero-visual-frame {
    box-shadow:
        0 1px 0 rgba(255, 255, 255, 0.04) inset,
        0 24px 60px -20px rgba(0, 0, 0, 0.7);
}

.hero-visual-meta {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 14px;
    font-family: var(--vp-font-family-mono);
    font-size: 11px;
    letter-spacing: 0.04em;
    color: var(--vp-c-text-3);
}

.meta-label {
    text-transform: lowercase;
}

.meta-live {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    text-transform: uppercase;
    font-size: 10px;
    letter-spacing: 0.12em;
    color: var(--vp-c-text-2);
}

.live-dot {
    width: 6px;
    height: 6px;
    border-radius: 999px;
    background: #34c759; /* Apple system green */
    box-shadow: 0 0 0 0 rgba(52, 199, 89, 0.45);
    animation: live-pulse 2.4s ease-out infinite;
}

@keyframes live-pulse {
    0%   { box-shadow: 0 0 0 0 rgba(52, 199, 89, 0.45); }
    70%  { box-shadow: 0 0 0 6px rgba(52, 199, 89, 0); }
    100% { box-shadow: 0 0 0 0 rgba(52, 199, 89, 0); }
}

.hero-visual-svg {
    width: 100%;
    height: 280px;
    display: block;
}

.seg-normal {
    fill: var(--vp-c-text-3);
    fill-opacity: 0.32;
}
.dark .seg-normal {
    fill-opacity: 0.42;
}

.seg-blocked {
    fill: #ff453a; /* Apple system red */
    fill-opacity: 0.95;
}

.drift {
    animation: drift var(--drift-duration, 36s) linear infinite;
    animation-delay: var(--drift-delay, 0s);
    will-change: transform;
}

@keyframes drift {
    from { transform: translateX(0); }
    to   { transform: translateX(-480px); }
}

.hero-visual-foot {
    display: flex;
    align-items: center;
    gap: 16px;
    padding-top: 12px;
    margin-top: 4px;
    border-top: 1px solid var(--vp-c-divider);
    font-family: var(--vp-font-family-mono);
    font-variant-numeric: tabular-nums;
}

.foot-stat {
    display: inline-flex;
    align-items: baseline;
    gap: 8px;
}

.stat-num {
    font-size: 15px;
    font-weight: 600;
    letter-spacing: -0.01em;
    color: var(--vp-c-text-1);
}

.stat-unit {
    font-size: 11px;
    color: var(--vp-c-text-3);
    margin-left: 1px;
}

.stat-key {
    font-size: 10px;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--vp-c-text-3);
}

.foot-stat--blocked .stat-num {
    color: #ff453a;
}

.foot-sep {
    flex: 1;
    height: 1px;
    background: var(--vp-c-divider);
}

@media (prefers-reduced-motion: reduce) {
    .drift {
        animation: none;
    }
    .live-dot {
        animation: none;
    }
}
</style>
