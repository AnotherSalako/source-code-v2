/**
 * Ambient backdrop the glass cards actually have something to refract —
 * large, saturated, soft-edged color blooms (drawn from the same severity/
 * secure palette used everywhere else, so it reads as "this app's colors
 * caught in frosted glass," not decoration borrowed from nowhere). Pure
 * CSS, no image asset, stays crisp at any viewport.
 */
export function Texture() {
  return (
    <div className="pointer-events-none fixed inset-0 -z-10 overflow-hidden bg-paper" aria-hidden="true">
      <div className="absolute -left-32 -top-40 h-[34rem] w-[34rem] rounded-full bg-[color:var(--color-risk-medium)]/[0.22] blur-[110px]" />
      <div className="absolute right-[-8rem] top-[-10rem] h-[38rem] w-[38rem] rounded-full bg-[color:var(--color-secure)]/[0.20] blur-[120px]" />
      <div className="absolute bottom-[-16rem] left-[8%] h-[36rem] w-[48rem] rounded-full bg-[color:var(--color-risk-high)]/[0.16] blur-[130px]" />
      <div className="absolute bottom-[10%] right-[5%] h-[26rem] w-[26rem] rounded-full bg-ink/[0.14] blur-[100px]" />
      <div className="absolute left-[35%] top-[30%] h-[22rem] w-[22rem] rounded-full bg-[color:var(--color-risk-critical)]/[0.08] blur-[110px]" />
      <div
        className="absolute inset-0 opacity-[0.04] mix-blend-overlay"
        style={{
          backgroundImage:
            "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='120' height='120'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E\")",
        }}
      />
    </div>
  );
}
