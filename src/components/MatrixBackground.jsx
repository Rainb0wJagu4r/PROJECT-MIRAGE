import React, { useEffect, useRef } from 'react';

export default function MatrixBackground({ isDarkMode }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    let animationFrameId;
    let isPaused = false;
    
    // Set sizing
    const resizeCanvas = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    resizeCanvas();

    // Throttling helpers (limit to 25 FPS)
    const fps = 25;
    const interval = 1000 / fps;
    let lastTime = performance.now();

    // Matrix drops initialization
    const fontSize = 16;
    let columns = Math.floor(canvas.width / fontSize);
    let drops = Array(columns).fill(0).map(() => Math.floor(Math.random() * -20));

    // Dynamic color selection based on theme
    const getColors = () => {
      if (isDarkMode) {
        return {
          fadeFill: 'rgba(5, 4, 8, 0.06)',
          headText: '#ffffff',
          bodyText: 'rgba(255, 255, 255, 0.35)',
          tailText: 'rgba(255, 255, 255, 0.15)'
        };
      } else {
        return {
          fadeFill: 'rgba(245, 244, 250, 0.06)',
          headText: '#130e24',
          bodyText: 'rgba(19, 14, 36, 0.3)',
          tailText: 'rgba(19, 14, 36, 0.12)'
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

      // Draw fading background
      ctx.fillStyle = colors.fadeFill;
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      ctx.font = `600 ${fontSize}px var(--font-mono)`;

      // Loop over drops
      for (let i = 0; i < drops.length; i++) {
        // Random binary number (0 or 1)
        const char = Math.random() > 0.5 ? '1' : '0';
        const x = i * fontSize;
        const y = drops[i] * fontSize;

        if (y >= 0 && y < canvas.height + fontSize) {
          // Draw stream characters with head-body-tail gradient coloring
          const roll = Math.random();
          if (roll > 0.95) {
            ctx.fillStyle = colors.headText;
          } else if (roll > 0.5) {
            ctx.fillStyle = colors.bodyText;
          } else {
            ctx.fillStyle = colors.tailText;
          }
          ctx.fillText(char, x, y);
        }

        // Increment Y position
        drops[i]++;

        // Random reset if drop hits bottom or randomly to create stagger
        if (y > canvas.height && Math.random() > 0.975) {
          drops[i] = 0;
        }
      }
    };

    // Start loop
    animationFrameId = requestAnimationFrame(draw);

    // Visibility and Focus tracking to reduce RAM/CPU when backgrounded
    const handleVisibilityChange = () => {
      if (document.hidden) {
        isPaused = true;
        cancelAnimationFrame(animationFrameId);
      } else {
        isPaused = false;
        lastTime = performance.now();
        animationFrameId = requestAnimationFrame(draw);
      }
    };

    const handleFocus = () => {
      isPaused = false;
      lastTime = performance.now();
      animationFrameId = requestAnimationFrame(draw);
    };

    const handleBlur = () => {
      isPaused = true;
      cancelAnimationFrame(animationFrameId);
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
        columns = Math.floor(canvas.width / fontSize);
        // Stagger drops randomly
        drops = Array(columns).fill(0).map(() => Math.floor(Math.random() * -20));
      }, 250);
    };
    window.addEventListener('resize', handleResize);

    return () => {
      cancelAnimationFrame(animationFrameId);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('focus', handleFocus);
      window.removeEventListener('blur', handleBlur);
      window.removeEventListener('resize', handleResize);
      clearTimeout(resizeTimer);
    };
  }, [isDarkMode]);

  return <canvas ref={canvasRef} className="matrix-background" />;
}
