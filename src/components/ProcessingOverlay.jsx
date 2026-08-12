import React, { useEffect, useRef } from 'react';
import { Shield, ShieldAlert, Loader2 } from 'lucide-react';

export default function ProcessingOverlay({ isOpen, title, steps = [], error = null, onClose }) {
  const logEndRef = useRef(null);

  useEffect(() => {
    if (logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [steps]);

  if (!isOpen) return null;

  return (
    <div className="overlay-backdrop">
      <div className="overlay-modal">
        <div className="scan-icon-wrapper" style={{ borderColor: error ? 'var(--color-red)' : 'var(--color-primary)' }}>
          {error ? (
            <ShieldAlert size={36} className="text-red" style={{ color: 'var(--color-red)' }} />
          ) : (
            <Shield size={36} className="brand-logo-icon" style={{ color: 'var(--color-primary)' }} />
          )}
        </div>

        <h2 className="scan-step-title" style={{ color: error ? 'var(--color-red)' : 'var(--text-main)' }}>
          {error ? 'FALLO EN LA OPERACIÓN' : title}
        </h2>

        <div className="scan-progress-log">
          {steps.map((step, idx) => (
            <div key={idx} className={`log-entry ${step.success !== false ? 'success' : 'error'}`}>
              <span className="log-bullet">{step.success !== false ? '▶' : '■'}</span>
              <span>{step.msg}</span>
            </div>
          ))}
          
          {!error && (
            <div className="log-entry" style={{ color: 'var(--color-cyan)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Loader2 className="animate-spin" size={12} style={{ animation: 'spin 1s linear infinite' }} />
              <span>Procesando flujo de datos criptográficos...</span>
            </div>
          )}
          <div ref={logEndRef} />
        </div>

        {error && (
          <div style={{ marginTop: '25px' }}>
            <p style={{ color: 'var(--color-red)', fontSize: '0.9rem', marginBottom: '15px', wordBreak: 'break-all' }}>
              {error}
            </p>
            <button className="btn-secondary" onClick={onClose} style={{ width: '100%' }}>
              Cerrar Consola
            </button>
          </div>
        )}
      </div>
      
      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        .animate-spin {
          animation: spin 1.5s linear infinite;
        }
      `}</style>
    </div>
  );
}
