import React, { useEffect, useState, useRef } from 'react';

export default function CyberpunkBackground({ isDarkMode }) {
  const canvasRef = useRef(null);
  
  // Geolocation state (defaulting to Mexico coordinates)
  const [location, setLocation] = useState({
    lat: 23.6345,
    lon: -102.5528,
    country: 'MEXICO'
  });

  // Fetch user location on mount
  useEffect(() => {
    fetch('https://ipapi.co/json/')
      .then((res) => res.json())
      .then((data) => {
        if (data.latitude && data.longitude) {
          setLocation({
            lat: data.latitude,
            lon: data.longitude,
            country: (data.country_name || 'MEXICO').toUpperCase()
          });
        }
      })
      .catch(() => {
        // Safe silent fallback to default Mexico coordinates
      });
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId;
    let isPaused = false;

    // Resize logic
    const resizeCanvas = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    resizeCanvas();

    // Throttling to 30 FPS
    const fps = 30;
    const interval = 1000 / fps;
    let lastTime = performance.now();

    // Cyberpunk animation states
    let gridOffset = 0;
    let laserY = 0;
    let rotationAngle = 0;
    
    // Hex streams variables
    const hexLinesCount = 20;
    const leftHexLines = Array(hexLinesCount).fill(0).map(() => generateHexLine());
    const rightHexLines = Array(hexLinesCount).fill(0).map(() => generateHexLine());
    let hexScrollTimer = 0;

    function generateHexLine() {
      const addr = Math.floor(Math.random() * 0xFFFFFF).toString(16).toUpperCase().padStart(6, '0');
      const bytes = Array(4).fill(0).map(() => 
        Math.floor(Math.random() * 256).toString(16).toUpperCase().padStart(2, '0')
      ).join(' ');
      return `0x${addr}  ${bytes}`;
    }

    // System logs scrolling
    const logMessages = [
      'SEC_HANDSHAKE: VERIFIED',
      'AES_GCM_CORE: LOCK_OK',
      'ENTROPY_SEED: STABLE',
      'METADATA_CLEANER: ENGAGED',
      'SHREDDER: TRIPLE_PASS_STABLE',
      'PQC_HYBRID: ECC_FALLBACK',
      'HW_UUID_HASH: CONFIRMED',
      'VOLATILE_RAM_SHRED: STABLE',
      'DECOY_BLOCK: ACTIVE',
      'XOR_SPLIT_GEN: LOADED'
    ];
    let activeLogs = Array(6).fill(0).map(() => logMessages[Math.floor(Math.random() * logMessages.length)]);
    let logTimer = 0;

    const labels = [
      '[0x9F:OK]', '[SYS:SECURE]', '[DECOY:ACTIVE]', '[SHRED:CONFIRMED]',
      '[WRAITH:ENCRYPT]', '[TTL:SECURE]', '[HARDWARE:LOCKED]', '[SEED:GEN]',
      '[HASH:SHA3]', '[CIPHER:AES256]', '[RAM:VOLATILE]', '[DUAL:KEY]',
      '[BYPASS:DENIED]', '[OVERFLOW:PROTECTED]', '[IP:127.0.0.1]', '[PORT:3001]',
      '[SEC_SWEEP:OK]', '[SHIELD_UP:99%]', '[SHREDDER:TRIPLE]', '[MEM_WIPE:PASS]'
    ];

    // Initialize floating telemetry nodes
    const nodeCount = 22;
    const createNode = () => {
      const type = Math.random() > 0.75 ? 'reticle' : 'text';
      return {
        x: Math.random() * canvas.width,
        y: (canvas.height * 0.45) + Math.random() * (canvas.height * 0.5),
        opacity: 0.1 + Math.random() * 0.6,
        speedY: -0.2 - Math.random() * 0.5,
        label: labels[Math.floor(Math.random() * labels.length)],
        type
      };
    };

    let nodes = Array(nodeCount).fill(0).map(() => createNode());

    // Generate static grid crosshair coordinates (+)
    const crosshairs = [];
    const rows = 6;
    const cols = 8;
    for (let r = 1; r < rows; r++) {
      for (let c = 1; c < cols; c++) {
        crosshairs.push({ r, c });
      }
    }

    // Coordinates for simplified continent wireframe polygons
    const continents = [
      // Americas (North & South)
      [
        [-120, 60], [-100, 65], [-80, 70], [-60, 60], [-50, 45], [-70, 15],
        [-40, -10], [-60, -40], [-70, -55], [-74, -55], [-70, -35], [-72, -15],
        [-80, 10], [-100, 18], [-120, 35], [-125, 50], [-120, 60]
      ],
      // Africa
      [
        [20, 35], [32, 31], [50, 12], [40, -15], [30, -32], [18, -34],
        [10, 5], [-15, 16], [-15, 30], [20, 35]
      ],
      // Eurasia (Europe & Asia)
      [
        [-10, 62], [10, 65], [30, 70], [60, 75], [100, 75], [140, 70],
        [142, 50], [130, 35], [120, 15], [100, 2], [80, 12], [45, 14],
        [35, 30], [15, 38], [-5, 38], [-10, 62]
      ],
      // Australia
      [
        [114, -22], [143, -15], [150, -34], [115, -34], [114, -22]
      ]
    ];

    // Theme adaptive colors (Solid Black in Dark Mode)
    const getColors = () => {
      if (isDarkMode) {
        return {
          bgFill: '#000000',
          gridStrokeRgb: '139, 92, 246', // Purple
          gridStrokeMaxOpacity: 0.18,
          gridRayStart: 'rgba(139, 92, 246, 0.01)',
          gridRayEnd: 'rgba(139, 92, 246, 0.22)',
          horizonGlow: 'rgba(6, 182, 212, 0.03)', // Cyan
          laserColor: 'rgba(6, 182, 212, 0.6)',
          laserGlow: 'rgba(6, 182, 212, 0.1)',
          vectorRings: 'rgba(139, 92, 246, 0.22)', // Purple rings
          globeFront: 'rgba(6, 182, 212, 0.45)', // Cyan front meridians
          globeBack: 'rgba(6, 182, 212, 0.08)',  // Dim cyan back meridians
          globeSilhouette: 'rgba(6, 182, 212, 0.22)',
          continentsColor: 'rgba(6, 182, 212, 0.55)', // Bright cyan outline for countries
          packetRgb: '139, 92, 246',
          sideHexColor: 'rgba(139, 92, 246, 0.18)',
          crosshairColor: 'rgba(6, 182, 212, 0.06)'
        };
      } else {
        return {
          bgFill: '#f5f4fa',
          gridStrokeRgb: '124, 58, 237', // Violet
          gridStrokeMaxOpacity: 0.12,
          gridRayStart: 'rgba(124, 58, 237, 0.01)',
          gridRayEnd: 'rgba(124, 58, 237, 0.15)',
          horizonGlow: 'rgba(8, 145, 178, 0.02)', // Cyan
          laserColor: 'rgba(8, 145, 178, 0.4)',
          laserGlow: 'rgba(8, 145, 178, 0.06)',
          vectorRings: 'rgba(124, 58, 237, 0.18)', // Violet rings
          globeFront: 'rgba(8, 145, 178, 0.35)', // Cyan front
          globeBack: 'rgba(8, 145, 178, 0.06)',  // Dim back
          globeSilhouette: 'rgba(8, 145, 178, 0.14)',
          continentsColor: 'rgba(8, 145, 178, 0.45)',
          packetRgb: '124, 58, 237',
          sideHexColor: 'rgba(124, 58, 237, 0.14)',
          crosshairColor: 'rgba(8, 145, 178, 0.04)'
        };
      }
    };

    let colors = getColors();

    const draw = (time) => {
      if (isPaused) return;
      animationFrameId = requestAnimationFrame(draw);

      const delta = time - lastTime;
      if (delta < interval) return;
      lastTime = time - (delta % interval);

      // 1. Solid background layer
      ctx.fillStyle = colors.bgFill;
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      const horizonY = canvas.height * 0.45;

      // 2. Static crosshair coordinate overlay (+)
      ctx.strokeStyle = colors.crosshairColor;
      ctx.lineWidth = 1;
      crosshairs.forEach(({ r, c }) => {
        const x = (c / cols) * canvas.width;
        const y = (r / rows) * canvas.height;
        ctx.beginPath();
        ctx.moveTo(x - 5, y); ctx.lineTo(x + 5, y);
        ctx.moveTo(x, y - 5); ctx.lineTo(x, y + 5);
        ctx.stroke();
      });

      // 3. Horizon Glow Mist (Synthwave backdrop)
      const glowGrad = ctx.createRadialGradient(
        canvas.width / 2, horizonY, 20,
        canvas.width / 2, horizonY, canvas.width / 2
      );
      glowGrad.addColorStop(0, colors.horizonGlow);
      glowGrad.addColorStop(1, 'rgba(0,0,0,0)');
      ctx.fillStyle = glowGrad;
      ctx.fillRect(0, horizonY - 120, canvas.width, 260);

      // --- NEW HOLOGRAPHIC SATELLITE HUD WIDGET (Centered Vertically on the Right) ---
      const globeRadius = 135; // Much larger radius!
      const globeCX = canvas.width - 230; // Positioned on the right side
      const globeCY = canvas.height * 0.48; // Centered vertically relative to the cards
      const tilt = 0.35; // tilt on X-axis (approx 20 deg)

      // Only render if screen is wide enough to prevent mobile collision
      if (canvas.width > 900) {
        rotationAngle += 0.005;

        // Concentric Rotating HUD Rings
        ctx.lineWidth = 1.2;
        ctx.strokeStyle = colors.vectorRings;
        
        // Outer arc sweep
        ctx.beginPath();
        ctx.arc(globeCX, globeCY, 195, rotationAngle, rotationAngle + Math.PI * 0.6);
        ctx.stroke();
        ctx.beginPath();
        ctx.arc(globeCX, globeCY, 195, rotationAngle + Math.PI, rotationAngle + Math.PI * 1.6);
        ctx.stroke();

        // Middle ring degree ticks
        for (let angle = 0; angle < Math.PI * 2; angle += Math.PI / 12) {
          const startX = globeCX + Math.cos(angle + rotationAngle * 0.5) * 160;
          const startY = globeCY + Math.sin(angle + rotationAngle * 0.5) * 160;
          const endX = globeCX + Math.cos(angle + rotationAngle * 0.5) * 168;
          const endY = globeCY + Math.sin(angle + rotationAngle * 0.5) * 168;
          ctx.beginPath();
          ctx.moveTo(startX, startY);
          ctx.lineTo(endX, endY);
          ctx.stroke();
        }

        // Inner dashed ring
        ctx.setLineDash([3, 8]);
        ctx.beginPath();
        ctx.arc(globeCX, globeCY, 150, -rotationAngle, -rotationAngle + Math.PI * 2);
        ctx.stroke();
        ctx.setLineDash([]); // Reset line dash

        // Draw silhouette outer ring of the globe
        ctx.strokeStyle = colors.globeSilhouette;
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.arc(globeCX, globeCY, globeRadius, 0, Math.PI * 2);
        ctx.stroke();

        // Draw Continents (Countries wireframe)
        ctx.lineWidth = 1.4;
        continents.forEach((polygon) => {
          ctx.beginPath();
          let firstPointDrawn = false;
          
          for (let i = 0; i < polygon.length; i++) {
            const [lonDeg, latDeg] = polygon[i];
            const latRad = (latDeg * Math.PI) / 180;
            const lonRad = (lonDeg * Math.PI) / 180 + rotationAngle;
            
            const x = globeRadius * Math.cos(latRad) * Math.sin(lonRad);
            const y = -globeRadius * Math.sin(latRad);
            const z = globeRadius * Math.cos(latRad) * Math.cos(lonRad);

            // Apply X-axis tilt
            const rx = x;
            const ry = y * Math.cos(tilt) - z * Math.sin(tilt);
            const rz = y * Math.sin(tilt) + z * Math.cos(tilt);

            const screenX = globeCX + rx;
            const screenY = globeCY + ry;

            // Only render line segments on the front-facing hemisphere (rz > 0)
            if (rz > 0) {
              ctx.strokeStyle = colors.continentsColor;
              if (!firstPointDrawn) {
                ctx.beginPath();
                ctx.moveTo(screenX, screenY);
                firstPointDrawn = true;
              } else {
                ctx.lineTo(screenX, screenY);
              }
            } else {
              // Break path to avoid wrapping across the back
              ctx.stroke();
              firstPointDrawn = false;
            }
          }
          ctx.stroke();
        });

        // Globe Latitudes (Parallels)
        const latSteps = 6;
        for (let j = 1; j < latSteps; j++) {
          const lat = -Math.PI / 2 + (j / latSteps) * Math.PI;
          
          for (let k = 0; k <= 36; k++) {
            const lon = (k / 36) * Math.PI * 2 + rotationAngle;
            const x = globeRadius * Math.cos(lat) * Math.sin(lon);
            const y = globeRadius * Math.sin(lat);
            const z = globeRadius * Math.cos(lat) * Math.cos(lon);

            const rx = x;
            const ry = y * Math.cos(tilt) - z * Math.sin(tilt);
            const rz = y * Math.sin(tilt) + z * Math.cos(tilt);

            ctx.strokeStyle = rz > 0 ? colors.globeBack : 'rgba(0,0,0,0)'; // Hide back parallels entirely to make front continents stand out clearly!
            ctx.lineWidth = 0.5;

            const screenX = globeCX + rx;
            const screenY = globeCY + ry;

            if (k === 0) {
              ctx.beginPath();
              ctx.moveTo(screenX, screenY);
            } else {
              ctx.lineTo(screenX, screenY);
              ctx.stroke();
              ctx.beginPath();
              ctx.moveTo(screenX, screenY);
            }
          }
        }

        // Globe Longitudes (Meridians)
        const lonSteps = 8;
        for (let j = 0; j < lonSteps; j++) {
          const lon = (j / lonSteps) * Math.PI * 2 + rotationAngle;
          
          for (let k = 0; k <= 24; k++) {
            const lat = -Math.PI / 2 + (k / 24) * Math.PI;
            const x = globeRadius * Math.cos(lat) * Math.sin(lon);
            const y = globeRadius * Math.sin(lat);
            const z = globeRadius * Math.cos(lat) * Math.cos(lon);

            const rx = x;
            const ry = y * Math.cos(tilt) - z * Math.sin(tilt);
            const rz = y * Math.sin(tilt) + z * Math.cos(tilt);

            ctx.strokeStyle = rz > 0 ? colors.globeBack : 'rgba(0,0,0,0)'; // Hide back meridians entirely for visual clarity
            ctx.lineWidth = 0.5;

            const screenX = globeCX + rx;
            const screenY = globeCY + ry;

            if (k === 0) {
              ctx.beginPath();
              ctx.moveTo(screenX, screenY);
            } else {
              ctx.lineTo(screenX, screenY);
              ctx.stroke();
              ctx.beginPath();
              ctx.moveTo(screenX, screenY);
            }
          }
        }

        // --- DYNAMIC GEOLOCATION DOT TARGET ---
        const latRad = (location.lat * Math.PI) / 180;
        const lonRad = (location.lon * Math.PI) / 180 + rotationAngle;

        const dotX = globeRadius * Math.cos(latRad) * Math.sin(lonRad);
        const dotY = -globeRadius * Math.sin(latRad);
        const dotZ = globeRadius * Math.cos(latRad) * Math.cos(lonRad);

        const drx = dotX;
        const dry = dotY * Math.cos(tilt) - dotZ * Math.sin(tilt);
        const drz = dotY * Math.sin(tilt) + dotZ * Math.cos(tilt);

        const lockColor = isDarkMode ? '#ef4444' : '#dc2626'; // Alert Red
        const screenDotX = globeCX + drx;
        const screenDotY = globeCY + dry;

        if (drz > 0) {
          // Point is on the front facing side
          ctx.fillStyle = lockColor;
          ctx.beginPath();
          ctx.arc(screenDotX, screenDotY, 5, 0, Math.PI * 2);
          ctx.fill();

          // Outer HUD target reticle box around coordinates
          ctx.strokeStyle = lockColor;
          ctx.lineWidth = 1.2;
          ctx.strokeRect(screenDotX - 8, screenDotY - 8, 16, 16);

          // Draw tracking pointer line
          ctx.strokeStyle = 'rgba(239, 68, 68, 0.4)';
          ctx.beginPath();
          ctx.moveTo(screenDotX, screenDotY);
          ctx.lineTo(screenDotX + 35, screenDotY - 20);
          ctx.stroke();

          // Coordinates detail box
          ctx.font = '600 9px "Fira Code", monospace';
          ctx.fillStyle = lockColor;
          ctx.fillText(`LOC: ${location.country}`, screenDotX + 40, screenDotY - 25);
          ctx.fillStyle = isDarkMode ? 'rgba(255, 255, 255, 0.6)' : 'rgba(19, 14, 36, 0.6)';
          ctx.fillText(`${location.lat.toFixed(2)}N ${location.lon.toFixed(2)}E`, screenDotX + 40, screenDotY - 13);
        } else {
          // Point is on the back side (occluded) - draw a faint tracking helper
          ctx.strokeStyle = isDarkMode ? 'rgba(239, 68, 68, 0.15)' : 'rgba(220, 38, 38, 0.15)';
          ctx.setLineDash([2, 4]);
          ctx.beginPath();
          ctx.arc(screenDotX, screenDotY, 3, 0, Math.PI * 2);
          ctx.stroke();
          ctx.setLineDash([]);
        }
      }

      // 5. Left and Right scrolling Hacking Hex Columns
      hexScrollTimer++;
      if (hexScrollTimer > 8) {
        hexScrollTimer = 0;
        leftHexLines.shift();
        leftHexLines.push(generateHexLine());
        rightHexLines.shift();
        rightHexLines.push(generateHexLine());
      }

      ctx.font = '500 11px "Fira Code", monospace';
      
      const leftColX = 30;
      const rightColX = canvas.width - 200;
      
      for (let i = 0; i < hexLinesCount; i++) {
        const y = 80 + i * 22;
        let edgeOpacity = 1;
        if (i < 3) edgeOpacity = i / 3;
        if (i > hexLinesCount - 4) edgeOpacity = (hexLinesCount - 1 - i) / 3;
        
        ctx.fillStyle = colors.sideHexColor.replace(/[\d\.]+\)$/, `${edgeOpacity * 0.18})`);
        ctx.fillText(leftHexLines[i], leftColX, y);
        ctx.fillText(rightHexLines[i], rightColX, y);
      }

      // 6. Glitch Calculations
      const isGlitching = Math.random() > 0.985;
      const glitchOffset = isGlitching ? (Math.random() - 0.5) * 20 : 0;

      // 7. Perspective Grid Rendering with depth gradients
      const rayCount = 22;
      const rayGrad = ctx.createLinearGradient(0, horizonY, 0, canvas.height);
      rayGrad.addColorStop(0, colors.gridRayStart);
      rayGrad.addColorStop(1, colors.gridRayEnd);
      ctx.strokeStyle = rayGrad;
      ctx.lineWidth = 1.2;

      for (let i = 0; i <= rayCount; i++) {
        const xBot = (i / rayCount) * canvas.width;
        ctx.beginPath();
        ctx.moveTo((canvas.width / 2) + glitchOffset, horizonY);
        ctx.lineTo(xBot + glitchOffset, canvas.height);
        ctx.stroke();
      }

      // Scrolling horizontal perspective gridlines
      gridOffset = (gridOffset + 0.65) % 100;
      const horizCount = 12;
      for (let i = 0; i < horizCount; i++) {
        const ratio = ((i + (gridOffset / 100)) % 1);
        const y = horizonY + Math.pow(ratio, 3.5) * (canvas.height - horizonY);
        ctx.strokeStyle = `rgba(${colors.gridStrokeRgb}, ${Math.pow(ratio, 2) * colors.gridStrokeMaxOpacity})`;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(canvas.width, y);
        ctx.stroke();
      }

      // 8. Sweeping Scan Laser
      laserY += 3.5;
      if (laserY > canvas.height) {
        laserY = 0;
      }
      
      const laserGrad = ctx.createLinearGradient(0, laserY - 10, 0, laserY + 10);
      laserGrad.addColorStop(0, 'rgba(0,0,0,0)');
      laserGrad.addColorStop(0.3, colors.laserGlow);
      laserGrad.addColorStop(0.5, colors.laserColor);
      laserGrad.addColorStop(0.7, colors.laserGlow);
      laserGrad.addColorStop(1, 'rgba(0,0,0,0)');
      ctx.fillStyle = laserGrad;
      ctx.fillRect(0, laserY - 10, canvas.width, 20);

      // 9. Floating Telemetry / Target Locking Reticles
      ctx.font = '700 9px "Fira Code", monospace';
      
      nodes.forEach((node) => {
        node.y += node.speedY;
        node.opacity -= 0.0025;

        // Reset telemetry node
        if (node.y < horizonY || node.opacity <= 0) {
          Object.assign(node, createNode());
        }

        const screenX = node.x + (isGlitching ? (Math.random() - 0.5) * 10 : 0);
        const opacityStr = `rgba(${colors.packetRgb}, ${node.opacity})`;

        if (node.type === 'reticle') {
          // Draw target locking HUD box
          const size = 18;
          ctx.strokeStyle = opacityStr;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(screenX - size, node.y - size / 2);
          ctx.lineTo(screenX - size, node.y - size);
          ctx.lineTo(screenX - size / 2, node.y - size);
          ctx.moveTo(screenX + size / 2, node.y - size);
          ctx.lineTo(screenX + size, node.y - size);
          ctx.lineTo(screenX + size, node.y - size / 2);
          ctx.moveTo(screenX - size, node.y + size / 2);
          ctx.lineTo(screenX - size, node.y + size);
          ctx.lineTo(screenX - size / 2, node.y + size);
          ctx.moveTo(screenX + size / 2, node.y + size);
          ctx.lineTo(screenX + size, node.y + size);
          ctx.lineTo(screenX + size, node.y + size / 2);
          ctx.stroke();

          ctx.fillStyle = opacityStr;
          ctx.fillRect(screenX - 1, node.y - 1, 2, 2);

          ctx.fillText(node.label, screenX + size + 4, node.y + 3);
        } else {
          ctx.fillStyle = opacityStr;
          ctx.fillText(node.label, screenX, node.y);
        }
      });

      // 10. Draw connecting mesh vector links
      ctx.lineWidth = 0.5;
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x;
          const dy = nodes[i].y - nodes[j].y;
          const dist = Math.sqrt(dx*dx + dy*dy);
          if (dist < 130) {
            const lineOpacity = (1 - dist / 130) * 0.08 * Math.min(nodes[i].opacity, nodes[j].opacity);
            ctx.strokeStyle = `rgba(${colors.packetRgb}, ${lineOpacity})`;
            ctx.beginPath();
            ctx.moveTo(nodes[i].x, nodes[i].y);
            ctx.lineTo(nodes[j].x, nodes[j].y);
            ctx.stroke();
          }
        }
      }

      // 11. Bottom-Left Scrolling System Hacking Logs
      logTimer++;
      if (logTimer > 40) {
        logTimer = 0;
        activeLogs.shift();
        activeLogs.push(logMessages[Math.floor(Math.random() * logMessages.length)]);
      }

      ctx.font = '600 9px "Fira Code", monospace';
      const logYBase = canvas.height - 180;
      activeLogs.forEach((logLine, index) => {
        const logOpacity = (index + 1) / activeLogs.length * 0.35;
        ctx.fillStyle = `rgba(${colors.packetRgb}, ${logOpacity})`;
        ctx.fillText(`> ${logLine}`, 30, logYBase + index * 16);
      });
    };

    // Safe RAF stacks controllers
    const startLoop = () => {
      cancelAnimationFrame(animationFrameId);
      animationFrameId = requestAnimationFrame(draw);
    };

    const stopLoop = () => {
      cancelAnimationFrame(animationFrameId);
    };

    // Start rendering
    startLoop();

    // Visibility handlers
    const handleVisibilityChange = () => {
      if (document.hidden) {
        isPaused = true;
        stopLoop();
      } else {
        isPaused = false;
        lastTime = performance.now();
        startLoop();
      }
    };

    const handleFocus = () => {
      if (isPaused) {
        isPaused = false;
        lastTime = performance.now();
        startLoop();
      }
    };

    const handleBlur = () => {
      isPaused = true;
      stopLoop();
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    window.addEventListener('focus', handleFocus);
    window.addEventListener('blur', handleBlur);

    // Debounced window resize handler
    let resizeTimer;
    const handleResize = () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        resizeCanvas();
        nodes = Array(nodeCount).fill(0).map(() => createNode());
      }, 250);
    };
    window.addEventListener('resize', handleResize);

    return () => {
      stopLoop();
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('focus', handleFocus);
      window.removeEventListener('blur', handleBlur);
      window.removeEventListener('resize', handleResize);
      clearTimeout(resizeTimer);
    };
  }, [isDarkMode, location]);

  return <canvas ref={canvasRef} className="cyberpunk-background" />;
}
