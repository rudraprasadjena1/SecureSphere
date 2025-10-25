/** @type {import('tailwindcss').Config} */
export default {
  // This tells Tailwind to scan all these files for class names.
  // Make sure this path matches your project structure.
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // You can customize your primary color here
        primary: '#6366F1', // Indigo-500
        background: {
          light: '#F9FAFB', // Gray-50
          dark: '#111827',   // Gray-900
        },
      },
      fontFamily: {
        // Ensure you are importing this font in your index.html
        display: ['Poppins', 'sans-serif'],
      },
    },
  },
  plugins: [],
}