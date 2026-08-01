/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#030712",       // ultra dark gray/slate
          card: "#111827",     // dark gray card
          border: "#1f2937",   // border slate
          primary: "#06b6d4",  // bright cyan glow
          secondary: "#8b5cf6",// purple highlight
          success: "#10b981",  // emerald green
          warning: "#f59e0b",  // warning orange
          danger: "#ef4444",   // error red
          text: "#f3f4f6",     // off-white text
          muted: "#9ca3af"     // gray text
        }
      }
    },
  },
  plugins: [],
}
