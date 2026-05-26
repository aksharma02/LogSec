import * as React from 'react';
import { cn } from '@/lib/utils';

// ==========================================
// BUTTON COMPONENT
// ==========================================
export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'outline' | 'destructive' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  loading?: boolean;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'primary', size = 'md', loading, children, ...props }, ref) => {
    return (
      <button
        ref={ref}
        disabled={loading || props.disabled}
        className={cn(
          'inline-flex items-center justify-center rounded-md font-medium transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:ring-offset-2 focus:ring-offset-slate-900 disabled:opacity-50 disabled:cursor-not-allowed active:scale-95',
          {
            // Primary (Cyan Glow Accent)
            'bg-cyan-500 text-slate-950 hover:bg-cyan-400 font-semibold shadow-lg shadow-cyan-500/10 hover:shadow-cyan-400/35':
              variant === 'primary',
            // Secondary (Dark Slate Accent)
            'bg-slate-800 text-slate-100 hover:bg-slate-700 border border-slate-700':
              variant === 'secondary',
            // Outline (Neon Borders Accent)
            'border border-slate-700 text-slate-300 hover:bg-slate-800 hover:text-white':
              variant === 'outline',
            // Destructive (Red Glow Accent)
            'bg-red-500 text-white hover:bg-red-400 shadow-lg shadow-red-500/10 hover:shadow-red-400/35':
              variant === 'destructive',
            // Ghost (Minimalist Accent)
            'text-slate-400 hover:bg-slate-800 hover:text-white': variant === 'ghost',
          },
          {
            'px-2.5 py-1.5 text-xs': size === 'sm',
            'px-4 py-2 text-sm': size === 'md',
            'px-6 py-3 text-base': size === 'lg',
          },
          className
        )}
        {...props}
      >
        {loading && (
          <svg
            className="animate-spin -ml-1 mr-2 h-4 w-4 text-current"
            fill="none"
            viewBox="0 0 24 24"
          >
            <circle
              className="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="4"
            />
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
            />
          </svg>
        )}
        {children}
      </button>
    );
  }
);
Button.displayName = 'Button';

// ==========================================
// CARD COMPONENTS
// ==========================================
export const Card = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn(
        'rounded-lg border border-slate-800/80 bg-slate-900/60 backdrop-blur-md text-slate-100 shadow-xl shadow-black/20',
        className
      )}
      {...props}
    />
  )
);
Card.displayName = 'Card';

export const CardHeader = ({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
  <div className={cn('flex flex-col space-y-1.5 p-6 border-b border-slate-800/50', className)} {...props} />
);
CardHeader.displayName = 'CardHeader';

export const CardTitle = ({ className, ...props }: React.HTMLAttributes<HTMLHeadingElement>) => (
  <h3 className={cn('text-lg font-semibold leading-none tracking-tight text-white', className)} {...props} />
);
CardTitle.displayName = 'CardTitle';

export const CardDescription = ({ className, ...props }: React.HTMLAttributes<HTMLParagraphElement>) => (
  <p className={cn('text-sm text-slate-400', className)} {...props} />
);
CardDescription.displayName = 'CardDescription';

export const CardContent = ({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
  <div className={cn('p-6', className)} {...props} />
);
CardContent.displayName = 'CardContent';

// ==========================================
// BADGE COMPONENT
// ==========================================
export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'default' | 'outline' | 'success';
}

export const Badge = ({ className, variant = 'default', ...props }: BadgeProps) => {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wider transition-colors duration-150',
        {
          'bg-red-500/15 text-red-400 border border-red-500/30': variant === 'critical',
          'bg-orange-500/15 text-orange-400 border border-orange-500/30': variant === 'high',
          'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30': variant === 'medium',
          'bg-blue-500/15 text-blue-400 border border-blue-500/30': variant === 'low',
          'bg-slate-500/15 text-slate-400 border border-slate-500/30': variant === 'info',
          'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30': variant === 'success',
          'bg-slate-800 text-slate-300 border border-slate-700': variant === 'default',
          'border border-slate-700 text-slate-400': variant === 'outline',
        },
        className
      )}
      {...props}
    />
  );
};
Badge.displayName = 'Badge';

// ==========================================
// PROGRESS COMPONENT
// ==========================================
export interface ProgressProps {
  value: number;
  className?: string;
  glow?: boolean;
}

export const Progress = ({ value, className, glow = true }: ProgressProps) => {
  const clampedValue = Math.min(100, Math.max(0, value));
  return (
    <div className={cn('h-2 w-full rounded-full bg-slate-800 overflow-hidden', className)}>
      <div
        className={cn(
          'h-full bg-cyan-500 rounded-full transition-all duration-500 ease-out',
          glow && 'shadow-[0_0_10px_rgba(6,182,212,0.6)]'
        )}
        style={{ width: `${clampedValue}%` }}
      />
    </div>
  );
};
Progress.displayName = 'Progress';

// ==========================================
// TABLE COMPONENTS
// ==========================================
export const Table = ({ className, ...props }: React.HTMLAttributes<HTMLTableElement>) => (
  <div className="w-full overflow-auto">
    <table className={cn('w-full border-collapse text-left text-sm', className)} {...props} />
  </div>
);
export const TableHeader = ({ className, ...props }: React.HTMLAttributes<HTMLTableSectionElement>) => (
  <thead className={cn('bg-slate-900/80 text-xs font-semibold uppercase tracking-wider text-slate-400 border-b border-slate-800', className)} {...props} />
);
export const TableBody = ({ className, ...props }: React.HTMLAttributes<HTMLTableSectionElement>) => (
  <tbody className={cn('divide-y divide-slate-800/50 bg-slate-950/20', className)} {...props} />
);
export const TableRow = ({ className, ...props }: React.HTMLAttributes<HTMLTableRowElement>) => (
  <tr className={cn('transition-colors hover:bg-slate-900/30', className)} {...props} />
);
export const TableHead = ({ className, ...props }: React.HTMLAttributes<HTMLTableCellElement>) => (
  <th className={cn('p-4 font-semibold text-slate-300', className)} {...props} />
);
export const TableCell = ({ className, ...props }: React.HTMLAttributes<HTMLTableCellElement>) => (
  <td className={cn('p-4 text-slate-300 font-mono align-middle', className)} {...props} />
);

// ==========================================
// TABS COMPONENTS
// ==========================================
interface TabsContextType {
  activeTab: string;
  setActiveTab: (value: string) => void;
}
const TabsContext = React.createContext<TabsContextType | undefined>(undefined);

export const Tabs = ({
  value,
  onValueChange,
  children,
  className,
}: {
  value: string;
  onValueChange: (val: string) => void;
  children: React.ReactNode;
  className?: string;
}) => {
  return (
    <TabsContext.Provider value={{ activeTab: value, setActiveTab: onValueChange }}>
      <div className={cn('space-y-4', className)}>{children}</div>
    </TabsContext.Provider>
  );
};

export const TabsList = ({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
  <div
    className={cn(
      'inline-flex h-10 items-center justify-start rounded-md bg-slate-950 p-1 border border-slate-800/80',
      className
    )}
    {...props}
  />
);

export const TabsTrigger = ({
  value,
  children,
  className,
}: {
  value: string;
  children: React.ReactNode;
  className?: string;
}) => {
  const context = React.useContext(TabsContext);
  if (!context) throw new Error('TabsTrigger must be used inside Tabs');
  const isActive = context.activeTab === value;

  return (
    <button
      onClick={() => context.setActiveTab(value)}
      className={cn(
        'inline-flex items-center justify-center rounded-sm px-3 py-1.5 text-sm font-medium transition-all focus-visible:outline-none disabled:pointer-events-none disabled:opacity-50',
        isActive
          ? 'bg-slate-800 text-cyan-400 font-semibold shadow-sm border border-slate-700/50'
          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/40',
        className
      )}
    >
      {children}
    </button>
  );
};

export const TabsContent = ({
  value,
  children,
  className,
}: {
  value: string;
  children: React.ReactNode;
  className?: string;
}) => {
  const context = React.useContext(TabsContext);
  if (!context) throw new Error('TabsContent must be used inside Tabs');
  if (context.activeTab !== value) return null;

  return <div className={cn('focus-visible:outline-none', className)}>{children}</div>;
};
