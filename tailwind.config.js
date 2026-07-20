/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        matte: '#0B0F10',
        secondary: '#111827',
        card: '#161B22',
        border: '#2A2F36',
        neon: {
          DEFAULT: '#39FF6A',
          dim: '#1FA34B',
          glow: 'rgba(57, 255, 106, 0.35)',
        },
        danger: {
          DEFAULT: '#FF3B4E',
          dim: '#7A1622',
        },
        warn: {
          DEFAULT: '#FFB020',
          dim: '#7A5A10',
        },
        info: {
          DEFAULT: '#3B9DFF',
          dim: '#173A66',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      boxShadow: {
        soft: '0 4px 24px rgba(0,0,0,0.35)',
        glow: '0 0 20px rgba(57, 255, 106, 0.25)',
        card: '0 1px 0 rgba(255,255,255,0.03) inset, 0 8px 24px rgba(0,0,0,0.4)',
      },
      backgroundImage: {
        'glass-gradient': 'linear-gradient(180deg, rgba(255,255,255,0.04) 0%, rgba(255,255,255,0.01) 100%)',
        'grid-fade': 'radial-gradient(circle at 1px 1px, rgba(255,255,255,0.06) 1px, transparent 0)',
      },
      keyframes: {
        pulseGlow: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.5' },
        },
        slideIn: {
          from: { transform: 'translateX(100%)' },
          to: { transform: 'translateX(0)' },
        },
        fadeIn: {
          from: { opacity: '0' },
          to: { opacity: '1' },
        },
      },
      animation: {
        pulseGlow: 'pulseGlow 2s ease-in-out infinite',
        slideIn: '0.25s ease-out slideIn',
        fadeIn: '0.2s ease-out fadeIn',
      },
    },
  },
  plugins: [],
}
