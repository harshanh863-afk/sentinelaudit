import * as React from "react";
import { cn } from "@/lib/utils";

const Progress = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement> & { value?: number }>(
  ({ className, value = 0, ...props }, ref) => (
    <div ref={ref} className={cn("relative h-2 w-full overflow-hidden rounded-full bg-cyber-700/50", className)} {...props}>
      <div
        className="h-full w-full flex-1 rounded-full bg-gradient-to-r from-blue-500 via-purple-500 to-cyan-500 transition-all duration-500"
        style={{ transform: `translateX(-${100 - Math.min(value, 100)}%)` } as any}
      />
    </div>
  )
);
Progress.displayName = "Progress";

export { Progress };
