import React, { useEffect, useRef } from 'react';

export default function CyberpunkBackground({ isDarkMode }) {
  const canvasRef = useRef(null);

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

    const labels = [
      '[0x9F:OK]', '[SYS:SECURE]', '[DECOY:ACTIVE]', '[SHRED:CONFIRMED]',
      '[WRAITH:ENCRYPT]', '[TTL:SECURE]', '[HARDWARE:LOCKED]', '[SEED:GEN]',
      '[HASH:SHA3]', '[CIPHER:AES256]', '[RAM:VOLATILE]', '[DUAL:KEY]',
      '[BYPASS:DENIED]', '[OVERFLOW:PROTECTED]', '[IP:127.0.0.1]', '[PORT:3001]',
      '[SEC_SWEEP:OK]', '[SHIELD_UP:99%]', '[SHREDDER:TRIPLE]', '[MEM_WIPE:PASS]'
    ];

    // Initialize floating telemetry nodes
    const nodeCount = 18;
    const createNode = () => {
      const type = Math.random() > 0.75 ? 'reticle' : 'text';
      return {
        x: Math.random() * canvas.width,
        y: (canvas.height * 0.45) + Math.random() * (canvas.height * 0.5),
        opacity: 0.1 + Math.random() * 0.6,
        speedY: -0.2 - Math.random() * 0.6,
        label: labels[Math.floor(Math.random() * labels.length)],
        type
      };
    };

    let nodes = Array(nodeCount).fill(0).map(() => createNode());

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
          vectorRings: 'rgba(6, 182, 212, 0.12)',
          packetRgb: '139, 92, 246'
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
          vectorRings: 'rgba(8, 145, 178, 0.08)',
          packetRgb: '124, 58, 237'
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

      // 2. Horizon Glow Mist (Synthwave backdrop)
      const glowGrad = ctx.createRadialGradient(
        canvas.width / 2, horizonY, 20,
        canvas.width / 2, horizonY, canvas.width / 2
      );
      glowGrad.addColorStop(0, colors.horizonGlow);
      glowGrad.addColorStop(1, 'rgba(0,0,0,0)');
      ctx.fillStyle = glowGrad;
      ctx.fillRect(0, horizonY - 120, canvas.width, 260);

      // 3. Hacking Cybernetic Vector Radar Rings (Concentric rotating arcs)
      rotationAngle += 0.005;
      ctx.lineWidth = 1;
      ctx.strokeStyle = colors.vectorRings;
      
      // Outer ring
      ctx.beginPath();
      ctx.arc(canvas.width / 2, horizonY, 180, rotationAngle, rotationAngle + Math.PI * 0.6);
      ctx.stroke();
      ctx.beginPath();
      ctx.arc(canvas.width / 2, horizonY, 180, rotationAngle + Math.PI, rotationAngle + Math.PI * 1.6);
      ctx.stroke();

      // Inner dashed ring
      ctx.setLineDash([4, 12]);
      ctx.beginPath();
      ctx.arc(canvas.width / 2, horizonY, 100, -rotationAngle, -rotationAngle + Math.PI * 2);
      ctx.stroke();
      ctx.setLineDash([]); // Reset line dash

      // 4. Glitch Calculations
      const isGlitching = Math.random() > 0.985;
      const glitchOffset = isGlitching ? (Math.random() - 0.5) * 20 : 0;

      // 5. Perspective Grid Rendering with depth gradients
      // Vertical converging rays fading into the horizon
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

      // Scrolling horizontal perspective gridlines with opacity depth fades
      gridOffset = (gridOffset + 0.65) % 100;
      const horizCount = 12;
      for (let i = 0; i < horizCount; i++) {
        const ratio = ((i + (gridOffset / 100)) % 1);
        // Exponential depth scaling
        const y = horizonY + Math.pow(ratio, 3.5) * (canvas.height - horizonY);
        // Opacity vanishes near horizon (ratio = 0) and gets solid near screen (ratio = 1)
        ctx.strokeStyle = `rgba(${colors.gridStrokeRgb}, ${Math.pow(ratio, 2) * colors.gridStrokeMaxOpacity})`;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(canvas.width, y);
        ctx.stroke();
      }

      // 6. Sweeping Scan Laser
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

      // 7. Floating Telemetry / Target Locking Reticles
      ctx.font = '700 9px "Fira Code", monospace';
      
      nodes.forEach((node) => {
        node.y += node.speedY;
        node.opacity -= 0.0025;

        // Reset telemetry node when out of bounds or faded
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
          // top-left
          ctx.moveTo(screenX - size, node.y - size / 2);
          ctx.lineTo(screenX - size, node.y - size);
          ctx.lineTo(screenX - size / 2, node.y - size);
          // top-right
          ctx.moveTo(screenX + size / 2, node.y - size);
          ctx.lineTo(screenX + size, node.y - size);
          ctx.lineTo(screenX + size, node.y - size / 2);
          // bottom-left
          ctx.moveTo(screenX - size, node.y + size / 2);
          ctx.lineTo(screenX - size, node.y + size);
          ctx.lineTo(screenX - size / 2, node.y + size);
          // bottom-right
          ctx.moveTo(screenX + size / 2, node.y + size);
          ctx.lineTo(screenX + size, node.y + size);
          ctx.lineTo(screenX + size, node.y + size / 2);
          ctx.stroke();

          // Small crosshair dot in center
          ctx.fillStyle = opacityStr;
          ctx.fillRect(screenX - 1, node.y - 1, 2, 2);

          // Lock text indicator
          ctx.fillText(node.label, screenX + size + 4, node.y + 3);
        } else {
          // Standard text stream packet
          ctx.fillStyle = opacityStr;
          ctx.fillText(node.label, screenX, node.y);
        }
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
  }, [isDarkMode]);

  return <canvas ref={canvasRef} className="cyberpunk-background" />;
}
