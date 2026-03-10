/* Deterministic acronym avatar generation from a group UUID + name. */
(function (global) {
  function generateGroupAcronym(id, name) {
    var hex = id.replace(/-/g, '');
    function h(o, l) { return parseInt(hex.slice(o, o + l), 16) || 0; }

    var hue = h(0, 4) % 360;
    var sat = 55 + h(4, 2) % 20;   // 55-74
    var lit = 38 + h(6, 2) % 16;   // 38-53

    var bg   = 'hsl(' + hue + ',' + sat + '%,90%)';
    var dark = 'hsl(' + hue + ',' + sat + '%,' + lit + '%)';

    // Derive initials: first letter of each alphabetic word, up to 3 chars, uppercase.
    // "&" sitting between two alpha words is kept as a connector (e.g. "I&C", "B&P").
    // Leading/trailing "&" and non-alpha non-& tokens are skipped.
    var words = (name || '').trim().split(/\s+/);
    var initials = '';
    for (var i = 0; i < words.length && initials.length < 3; i++) {
      if (/^[A-Za-z]/.test(words[i])) {
        initials += words[i][0].toUpperCase();
      } else if (
        words[i] === '&' &&
        initials.length > 0 &&
        i + 1 < words.length &&
        /^[A-Za-z]/.test(words[i + 1])
      ) {
        initials += '&';
      }
    }
    if (!initials) { initials = '?'; }

    var fontSize = initials.length === 1 ? 36 : initials.length === 2 ? 28 : 22;

    // Measure the actual glyph bounding box so the SVG baseline is placed at
    // exactly the right position to centre the caps in the circle.
    //
    // y = 32 + (actualBoundingBoxAscent - actualBoundingBoxDescent) / 2
    //
    // This puts the glyph's visual centre on the circle's centre (y=32)
    // regardless of font metrics or letter count.  Falls back to 32 if the
    // Canvas API is unavailable.
    var textY = 32;
    try {
      var _c = document.createElement('canvas').getContext('2d');
      _c.font = '700 ' + fontSize + 'px system-ui, sans-serif';
      var _m = _c.measureText(initials); // raw string — canvas works with real text
      textY = 32 + (_m.actualBoundingBoxAscent - _m.actualBoundingBoxDescent) / 2;
    } catch (e) {}

    // Escape & for SVG XML; the canvas measurement above used the raw string.
    var svgText = initials.replace(/&/g, '&amp;');

    var svg =
      '<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">' +
      '<circle cx="32" cy="32" r="32" fill="' + bg + '"/>' +
      '<text x="32" y="' + textY.toFixed(2) + '" text-anchor="middle"' +
      ' font-family="system-ui,sans-serif" font-weight="700"' +
      ' font-size="' + fontSize + '" fill="' + dark + '"' +
      ' stroke="' + dark + '" stroke-width="0.5" paint-order="stroke fill">' +
      svgText +
      '</text></svg>';

    return {
      color: dark,
      image: 'data:image/svg+xml,' + encodeURIComponent(svg)
    };
  }

  global.generateGroupAcronym = generateGroupAcronym;
})(window);
