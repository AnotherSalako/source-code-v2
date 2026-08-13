/**
 * Soft, grayscale, out-of-focus ambient backdrop — the "frosted glass over
 * something organic" quality of the reference, without pulling in an image
 * asset. Pure CSS so it stays crisp at any viewport and costs nothing to load.
 */
export function Texture() {
  return (
    <div className="pointer-events-none fixed inset-0 -z-10 overflow-hidden bg-paper" aria-hidden="true">
      <div className="absolute -left-40 -top-40 h-[36rem] w-[36rem] rounded-full bg-ink/[0.05] blur-[100px]" />
      <div className="absolute right-[-10rem] top-[-6rem] h-[28rem] w-[28rem] rounded-full bg-ink/[0.04] blur-[110px]" />
      <div className="absolute bottom-[-14rem] left-[20%] h-[30rem] w-[42rem] rounded-full bg-ink/[0.035] blur-[120px]" />
      <div
        className="absolute inset-0 opacity-[0.025]"
        style={{
          backgroundImage:
            "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='120' height='120'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E\")",
        }}
      />
    </div>
  );
}
