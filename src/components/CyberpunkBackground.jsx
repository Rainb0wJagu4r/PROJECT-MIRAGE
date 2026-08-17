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

    const labels = [
      '[0x9F:OK]', '[SYS:SEC]', '[DECOY:ACTIVE]', '[SHRED:CONFIRMED]',
      '[WRAITH:ENCRYPT]', '[TTL:SECURE]', '[HARDWARE:LOCKED]', '[SEED:GEN]',
      '[HASH:SHA3]', '[CIPHER:AES256]', '[RAM:VOLATILE]', '[DUAL:KEY]'
    ];

    // Initialize floating data packet nodes
    const nodeCount = 8;
    let nodes = Array(nodeCount).fill(0).map(() => ({
      x: Math.random() * canvas.width,
      y: (canvas.height * 0.45) + Math.random() * (canvas.height * 0.55),
      opacity: 0.1 + Math.random() * 0.5,
      speedY: -0.5 - Math.random() * 1.5,
      label: labels[Math.floor(Math.random() * labels.length)]
    }));

    // Theme adaptive colors
    const getColors = () => {
      if (isDarkMode) {
        return {
          bgFill: '#050408',
          gridStroke: 'rgba(139, 92, 246, 0.08)',
          horizonGlow: 'rgba(6, 182, 212, 0.03)',
          laserColor: 'rgba(6, 182, 212, 0.6)',
          laserGlow: 'rgba(6, 182, 212, 0.1)',
          packetRgb: '139, 92, 246'
        };
      } else {
        return {
          bgFill: '#f5f4fa',
          gridStroke: 'rgba(124, 58, 237, 0.05)',
          horizonGlow: 'rgba(8, 145, 178, 0.02)',
          laserColor: 'rgba(8, 145, 178, 0.4)',
          laserGlow: 'rgba(8, 145, 178, 0.08)',
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

      // 1. Draw base background
      ctx.fillStyle = colors.bgFill;
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      const horizonY = canvas.height * 0.45;

      // 2. Horizon Glow Mist
      const glowGrad = ctx.createRadialGradient(
        canvas.width / 2, horizonY, 50,
        canvas.width / 2, horizonY, canvas.width / 2
      );
      glowGrad.addColorStop(0, colors.horizonGlow);
      glowGrad.addColorStop(1, 'rgba(0,0,0,0)');
      ctx.fillStyle = glowGrad;
      ctx.fillRect(0, horizonY - 100, canvas.width, 250);

      // 3. Glitch Calculations
      const isGlitching = Math.random() > 0.98;
      const glitchOffset = isGlitching ? (Math.random() - 0.5) * 15 : 0;

      // 4. Perspective Grid Rendering
      ctx.lineWidth = 1;
      ctx.strokeStyle = colors.gridStroke;

      // Vertical converging rays
      const rayCount = 18;
      for (let i = 0; i <= rayCount; i++) {
        const xBot = (i / rayCount) * canvas.width;
        ctx.beginPath();
        ctx.moveTo((canvas.width / 2) + glitchOffset, horizonY);
        ctx.lineTo(xBot + glitchOffset, canvas.height);
        ctx.stroke();
      }

      // Scrolling horizontal perspective gridlines
      gridOffset = (gridOffset + 0.8) % 100;
      const horizCount = 10;
      for (let i = 0; i < horizCount; i++) {
        const ratio = ((i + (gridOffset / 100)) % 1);
        // Exponential scale for perfect 3D perspective depth spacing
        const y = horizonY + Math.pow(ratio, 3) * (canvas.height - horizonY);
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(canvas.width, y);
        ctx.stroke();
      }

      // 5. Sweeping Laser Scanner
      laserY += 3;
      if (laserY > canvas.height) {
        laserY = 0;
      }
      
      const laserGrad = ctx.createLinearGradient(0, laserY - 8, 0, laserY + 8);
      laserGrad.addColorStop(0, 'rgba(0,0,0,0)');
      laserGrad.addColorStop(0.3, colors.laserGlow);
      laserGrad.addColorStop(0.5, colors.laserColor);
      laserGrad.addColorStop(0.7, colors.laserGlow);
      laserGrad.addColorStop(1, 'rgba(0,0,0,0)');
      ctx.fillStyle = laserGrad;
      ctx.fillRect(0, laserY - 8, canvas.width, 16);

      // 6. Floating Digital Coordinate Packets
      ctx.font = '600 10px "Fira Code", monospace';
      nodes.forEach((node) => {
        node.y += node.speedY;
        node.opacity -= 0.003;

        // Reset off-screen or faded nodes
        if (node.y < horizonY || node.opacity <= 0) {
          node.x = Math.random() * canvas.width;
          node.y = horizonY + Math.random() * (canvas.height * 0.5);
          node.opacity = 0.2 + Math.random() * 0.6;
          node.speedY = -0.3 - Math.random() * 0.7;
          node.label = labels[Math.floor(Math.random() * labels.length)];
        }

        const screenX = node.x + (isGlitching ? (Math.random() - 0.5) * 8 : 0);
        ctx.fillStyle = `rgba(${colors.packetRgb}, ${node.opacity})`;
        ctx.fillText(node.label, screenX, node.y);
      });
    };

    // Prevent duplicate requestAnimationFrame stacks
    const startLoop = () => {
      cancelAnimationFrame(animationFrameId);
      animationFrameId = requestAnimationFrame(draw);
    };

    const stopLoop = () => {
      cancelAnimationFrame(animationFrameId);
    };

    // Start loop execution
    startLoop();

    // Visibility state changes and window focus tracking
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
        // Redraw coordinates based on new bounds
        nodes = Array(nodeCount).fill(0).map(() => ({
          x: Math.random() * canvas.width,
          y: (canvas.height * 0.45) + Math.random() * (canvas.height * 0.55),
          opacity: 0.1 + Math.random() * 0.5,
          speedY: -0.3 - Math.random() * 0.7,
          label: labels[Math.floor(Math.random() * labels.length)]
        }));
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
