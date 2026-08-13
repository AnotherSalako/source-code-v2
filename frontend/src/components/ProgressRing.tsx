import { useEffect, useState } from "react";

interface ProgressRingProps {
  value: number; // 0-100
  size?: number;
  stroke?: number;
  trackClassName?: string;
  progressClassName?: string;
  label?: string;
  sublabel?: string;
}

export function ProgressRing({
  value,
  size = 108,
  stroke = 10,
  trackClassName = "stroke-line",
  progressClassName = "stroke-paper",
  label,
  sublabel,
}: ProgressRingProps) {
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (Math.min(100, Math.max(0, value)) / 100) * circumference;

  // Entrance is a transform/opacity tween (compositor-only, no layout or
  // paint per frame) rather than animating stroke-dashoffset directly —
  // dashoffset is set once, at its final value, and never transitions.
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    const id = requestAnimationFrame(() => setMounted(true));
    return () => cancelAnimationFrame(id);
  }, []);

  return (
    <div
      className={`relative inline-flex items-center justify-center transition-[transform,opacity] duration-700 ease-out ${
        mounted ? "scale-100 opacity-100" : "scale-75 opacity-0"
      }`}
      style={{ width: size, height: size }}
    >
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} strokeWidth={stroke} fill="none" className={trackClassName} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          strokeWidth={stroke}
          fill="none"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className={progressClassName}
        />
      </svg>
      <div className="absolute flex flex-col items-center justify-center">
        {label && <span className="text-lg font-bold leading-none">{label}</span>}
        {sublabel && <span className="mt-1 text-[10px] uppercase tracking-wide opacity-60">{sublabel}</span>}
      </div>
    </div>
  );
}
