/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./views/**/*.{html,js,php}",
    "./public/**/*.{html,js,php}",
    "./src/**/*.{html,js,php}",
    "./*.{html,js,php}"
  ],
  theme: {
    extend: {
      colors: {
        gold: {
          50: '#FEF9E8',
          100: '#FDF0C4',
          200: '#FAE190',
          300: '#F7D15C',
          400: '#F4C029',
          500: '#E5AD0F',
          600: '#B98A0C',
          700: '#8E6809',
          800: '#624605',
          900: '#352503',
        },
        gray: {
          50: '#F9FAFB',
          100: '#F3F4F6',
          200: '#E5E7EB',
          300: '#D1D5DB',
          400: '#9CA3AF',
          500: '#6B7280',
          600: '#4B5563',
          700: '#374151',
          800: '#1F2937',
          900: '#111827',
        }
      },
      fontFamily: {
        'sans': ['Roboto', 'sans-serif'],
        'heading': ['Poppins', 'sans-serif'],
      },
      boxShadow: {
        'custom': '0 4px 6px rgba(0, 0, 0, 0.1)',
        'hover': '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
        'card': '0 10px 20px rgba(0, 0, 0, 0.05), 0 6px 6px rgba(0, 0, 0, 0.03)',
      }
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
  ],
}