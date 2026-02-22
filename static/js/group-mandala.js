/* Deterministic mandala + color generation from a group UUID. */
(function (global) {
  function generateGroupMandala(id) {
    var hex = id.replace(/-/g, '');
    function h(o, l) { return parseInt(hex.slice(o, o + l), 16) || 0; }

    var hue = h(0, 4) % 360;
    var sat = 55 + h(4, 2) % 20;       // 55–74
    var lit = 38 + h(6, 2) % 16;       // 38–53
    var n1  = 4 + h(8, 2) % 6;         // inner petals: 4–9
    var n2  = 8 + h(10, 2) % 5;        // outer points: 8–12
    var v   = h(12, 2) % 4;            // shape variant: 0–3
    var tw  = (h(14, 2) / 255) * Math.PI; // rotation twist: 0–π

    var bg   = 'hsl(' + hue + ',' + sat + '%,92%)';
    var dark = 'hsl(' + hue + ',' + sat + '%,' + lit + '%)';
    var mid  = 'hsl(' + hue + ',' + sat + '%,' + (lit + 22) + '%)';
    var dot  = 'hsl(' + hue + ',' + (sat + 5) + '%,' + (lit - 6) + '%)';
    var TAU  = 2 * Math.PI;

    var p = ['<circle cx="32" cy="32" r="32" fill="' + bg + '"/>'];

    // Outer ring of dots or diamonds
    for (var i = 0; i < n2; i++) {
      var a = (i / n2) * TAU + tw;
      var x = (32 + 25 * Math.cos(a)).toFixed(2);
      var y = (32 + 25 * Math.sin(a)).toFixed(2);
      if (v < 2) {
        p.push(
          '<circle cx="' + x + '" cy="' + y + '" r="2.5"' +
          ' fill="' + dot + '" opacity="0.85"/>'
        );
      } else {
        var deg = (a * 180 / Math.PI + 45).toFixed(1);
        p.push(
          '<rect x="' + (parseFloat(x) - 2.5).toFixed(2) +
          '" y="' + (parseFloat(y) - 2.5).toFixed(2) +
          '" width="5" height="5" fill="' + dot + '" opacity="0.85"' +
          ' transform="rotate(' + deg + ',' + x + ',' + y + ')"/>'
        );
      }
    }

    // Middle petal ring
    for (var j = 0; j < n1; j++) {
      var a2  = (j / n1) * TAU + tw;
      var px  = (32 + 16 * Math.cos(a2)).toFixed(2);
      var py  = (32 + 16 * Math.sin(a2)).toFixed(2);
      var rot = (a2 * 180 / Math.PI).toFixed(1);
      var erx = (v % 2 === 0) ? 7 : 4;
      var ery = (v % 2 === 0) ? 3 : 6;
      p.push(
        '<ellipse cx="' + px + '" cy="' + py +
        '" rx="' + erx + '" ry="' + ery + '" fill="' + mid +
        '" transform="rotate(' + rot + ',' + px + ',' + py + ')"/>'
      );
    }

    // Centre jewel
    p.push('<circle cx="32" cy="32" r="9" fill="' + dark + '"/>');
    p.push('<circle cx="32" cy="32" r="4.5" fill="' + bg + '"/>');

    var svg =
      '<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">' +
      p.join('') + '</svg>';

    return {
      color: dark,
      image: 'data:image/svg+xml,' + encodeURIComponent(svg)
    };
  }

  global.generateGroupMandala = generateGroupMandala;
})(window);
