from cairosvg import svg2png

# Конвертируем SVG в PNG
svg2png(url='backend/static/images/logo.svg', write_to='backend/static/images/logo.png', output_width=200, output_height=200) 