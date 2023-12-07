/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./templates/**/*.jinja2'],
  theme: {
    extend: {},
  },
  plugins: [
    require('@tailwindcss/typography'),
    require('@tailwindcss/forms'),
  ],
}

