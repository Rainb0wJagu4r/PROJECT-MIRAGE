import React, { useState } from 'react';
import { 
  Archive, 
  Key, 
  Lock, 
  Folder, 
  Unlock, 
  CheckCircle, 
  AlertTriangle, 
  Terminal, 
  RefreshCw, 
  Eye, 
  EyeOff, 
  FileText,
  ShieldCheck,
  HardDrive
} from 'lucide-react';
import PathInput from './PathInput';
import api from '../api';

const restoreTrans = {
  es: {
    title: "RESTAURACIÓN DE VAULT DE EMERGENCIA",
    subtitle: "Descifra y recupera los archivos empaquetados en un contenedor blindado (.wraith) verificando firmas de integridad.",
    vaultPathLabel: "Ruta del Contenedor Vault Cifrado (.wraith)",
    vaultPathPlaceholder: "Ej: C:\\Users\\Usuario\\MirageVault\\Emergencia_VAULT_2026-08-26.wraith",
    passLabel: "Contraseña Maestra del Vault",
    passPlaceholder: "Ingresa la contraseña con la que fue cifrado el vault...",
    dfPassLabel: "Segundo Secreto (Si fue utilizado al cifrar)",
    dfPassPlaceholder: "Segundo secreto opcional...",
    restoreDirLabel: "Directorio de Destino para la Restauración",
    restoreDirPlaceholder: "Ej: C:\\Users\\Usuario\\RestoredFiles (Dejar vacío para defecto)",
    restoreBtn: "Descifrar y Restaurar Vault",
    restoring: "DESCIFRANDO Y VERIFICANDO INTEGRIDAD...",
    successTitle: "¡VAULT RESTAURADO EXITOSAMENTE!",
    successDesc: "Todos los archivos han sido descifrados, autenticados y guardados en su ubicación de destino.",
    restoredLocation: "Directorio de Restauración:",
    filesCount: "Archivos Recuperados:",
    colRelPath: "Ruta Relativa",
    colSize: "Tamaño",
    colSha3: "Hash SHA3-256",
    colIntegrity: "Integridad",
    hashValid: "✓ Válida",
    hashInvalid: "✗ Discrepancia",
    terminalTitle: "REGISTRO DE PROCESO DE RESTAURACIÓN",
    errorRequired: "Debes ingresar la ruta del Vault y la Contraseña Maestra."
  },
  en: {
    title: "EMERGENCY VAULT RESTORATION",
    subtitle: "Decrypt and restore all files packaged into an armored container (.wraith) with cryptographic integrity verification.",
    vaultPathLabel: "Armored Vault Container Path (.wraith)",
    vaultPathPlaceholder: "E.g., C:\\Users\\User\\MirageVault\\Emergencia_VAULT_2026-08-26.wraith",
    passLabel: "Master Vault Password",
    passPlaceholder: "Enter password used during emergency encryption...",
    dfPassLabel: "Secondary Secret (If configured during encryption)",
    dfPassPlaceholder: "Optional secondary secret...",
    restoreDirLabel: "Destination Directory for Restored Files",
    restoreDirPlaceholder: "E.g., C:\\Users\\User\\RestoredFiles (Leave empty for default)",
    restoreBtn: "Decrypt & Restore Vault",
    restoring: "DECRYPTING & VERIFYING INTEGRITY...",
    successTitle: "VAULT RESTORED SUCCESSFULLY!",
    successDesc: "All assets have been decrypted, authenticated, and saved to the target location.",
    restoredLocation: "Restoration Directory:",
    filesCount: "Recovered Files:",
    colRelPath: "Relative Path",
    colSize: "Size",
    colSha3: "SHA3-256 Checksum",
    colIntegrity: "Integrity",
    hashValid: "✓ Valid",
    hashInvalid: "✗ Mismatch",
    terminalTitle: "RESTORATION AUDIT TRAIL",
    errorRequired: "Vault path and Master Password are required."
  }
};

export default function EmergencyRestore({ lang = 'es' }) {
  const t = restoreTrans[lang] || restoreTrans.es;

  const [vaultPath, setVaultPath] = useState('');
  const [password, setPassword] = useState('');
  const [showPass, setShowPass] = useState(false);
  const [doubleFactorPassword, setDoubleFactorPassword] = useState('');
  const [showDfPass, setShowDfPass] = useState(false);
  const [restoreDir, setRestoreDir] = useState('');

  const [isRestoring, setIsRestoring] = useState(false);
  const [restoreLogs, setRestoreLogs] = useState([]);
  const [restoreResult, setRestoreResult] = useState(null);
  const [errorMessage, setErrorMessage] = useState('');

  const handleRestore = async () => {
    setErrorMessage('');
    if (!vaultPath || !password) {
      setErrorMessage(t.errorRequired);
      return;
    }

    setIsRestoring(true);
    setRestoreLogs([]);
    setRestoreResult(null);

    try {
      const data = await api.restoreEmergency({
        vaultPath,
        password,
        secondFactor: doubleFactorPassword || '',
        restoreLocation: restoreDir || ''
      });

      if (data && data.steps) {
        setRestoreLogs(data.steps);
      }
      if (data && data.success) {
        setRestoreResult(data);
      } else {
        setErrorMessage(data?.error || 'Restoration failed');
      }
    } catch (err) {
      setErrorMessage(err.message);
    } finally {
      setIsRestoring(false);
    }
  };

  return (
    <div className="emergency-restore-container animate-fade-in">
      <div className="section-header" style={{ marginBottom: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div className="status-indicator-icon pulse-glow" style={{ background: 'rgba(6, 182, 212, 0.2)', border: '1px solid var(--color-cyan)' }}>
            <Unlock size={24} style={{ color: 'var(--color-cyan)' }} />
          </div>
          <div>
            <h2 className="brand-title" style={{ fontSize: '1.4rem' }}>{t.title}</h2>
            <p className="brand-subtitle" style={{ fontSize: '0.85rem' }}>{t.subtitle}</p>
          </div>
        </div>
      </div>

      {errorMessage && (
        <div className="status-banner status-banner-error" style={{ marginBottom: '20px' }}>
          <AlertTriangle size={18} />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* FORM INPUTS */}
      <div className="dashboard-card" style={{ marginBottom: '24px' }}>
        <PathInput
          value={vaultPath}
          onChange={setVaultPath}
          label={t.vaultPathLabel}
          placeholder={t.vaultPathPlaceholder}
          icon={Archive}
        />

        <div className="form-group" style={{ marginTop: '16px' }}>
          <label className="form-label">{t.passLabel}</label>
          <div className="form-input-wrapper">
            <Key className="form-input-icon" size={18} />
            <input 
              type={showPass ? 'text' : 'password'}
              className="form-input" 
              value={password} 
              onChange={(e) => setPassword(e.target.value)} 
              placeholder={t.passPlaceholder}
            />
            <button
              type="button"
              className="password-toggle-btn"
              onClick={() => setShowPass(!showPass)}
            >
              {showPass ? <EyeOff size={18} /> : <Eye size={18} />}
            </button>
          </div>
        </div>

        <div className="form-group">
          <label className="form-label">{t.dfPassLabel}</label>
          <div className="form-input-wrapper">
            <Lock className="form-input-icon" size={18} />
            <input 
              type={showDfPass ? 'text' : 'password'}
              className="form-input" 
              value={doubleFactorPassword} 
              onChange={(e) => setDoubleFactorPassword(e.target.value)} 
              placeholder={t.dfPassPlaceholder}
            />
            <button
              type="button"
              className="password-toggle-btn"
              onClick={() => setShowDfPass(!showDfPass)}
            >
              {showDfPass ? <EyeOff size={18} /> : <Eye size={18} />}
            </button>
          </div>
        </div>

        <div style={{ marginTop: '16px' }}>
          <PathInput
            value={restoreDir}
            onChange={setRestoreDir}
            label={t.restoreDirLabel}
            placeholder={t.restoreDirPlaceholder}
            icon={Folder}
          />
        </div>

        <div style={{ marginTop: '24px', display: 'flex', justifyContent: 'flex-end' }}>
          <button
            type="button"
            className="btn-primary"
            onClick={handleRestore}
            disabled={isRestoring}
            style={{ padding: '14px 28px', fontSize: '0.95rem' }}
          >
            {isRestoring ? <RefreshCw className="spin" size={18} /> : <Unlock size={18} />}
            {isRestoring ? t.restoring : t.restoreBtn}
          </button>
        </div>
      </div>

      {/* RESTORE RESULTS */}
      {restoreResult && (
        <div className="dashboard-card animate-fade-in" style={{ marginBottom: '24px', border: '1px solid var(--color-green)', background: 'rgba(16, 185, 129, 0.05)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
            <CheckCircle size={28} style={{ color: 'var(--color-green)' }} />
            <div>
              <h3 style={{ fontFamily: 'var(--font-orbitron)', fontSize: '1.1rem', color: 'var(--color-green)' }}>{t.successTitle}</h3>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>{t.successDesc}</p>
            </div>
          </div>

          <div style={{ marginBottom: '16px', fontSize: '0.85rem' }}>
            <div><strong>{t.restoredLocation}</strong> {restoreResult.restoreDir}</div>
            <div><strong>{t.filesCount}</strong> {restoreResult.fileCount}</div>
          </div>

          {restoreResult.files && restoreResult.files.length > 0 && (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem', textAlign: 'left' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)', color: 'var(--text-muted)' }}>
                    <th style={{ padding: '8px' }}>{t.colRelPath}</th>
                    <th style={{ padding: '8px' }}>{t.colSize}</th>
                    <th style={{ padding: '8px' }}>{t.colSha3}</th>
                    <th style={{ padding: '8px' }}>{t.colIntegrity}</th>
                  </tr>
                </thead>
                <tbody>
                  {restoreResult.files.map((file, idx) => (
                    <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                      <td style={{ padding: '8px', fontWeight: 500 }}>{file.relPath}</td>
                      <td style={{ padding: '8px' }}>{(file.size / 1024).toFixed(1)} KB</td>
                      <td style={{ padding: '8px', fontFamily: 'var(--font-mono)', fontSize: '0.7rem' }}>
                        {file.sha3 ? `${file.sha3.substring(0, 16)}...` : '-'}
                      </td>
                      <td style={{ padding: '8px' }}>
                        <span style={{ 
                          padding: '2px 6px', 
                          background: file.hashMatches ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)', 
                          color: file.hashMatches ? 'var(--color-green)' : 'var(--color-red)', 
                          borderRadius: '4px', 
                          fontSize: '0.7rem' 
                        }}>
                          {file.hashMatches ? t.hashValid : t.hashInvalid}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* LOG TERMINAL */}
      {(restoreLogs.length > 0 || isRestoring) && (
        <div className="dashboard-card">
          <div className="card-header" style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <Terminal size={18} style={{ color: 'var(--color-cyan)' }} />
            <h3 style={{ fontFamily: 'var(--font-orbitron)', fontSize: '0.95rem' }}>{t.terminalTitle}</h3>
          </div>
          <div style={{ 
            background: 'rgba(5, 4, 8, 0.95)', 
            border: '1px solid var(--border)', 
            borderRadius: '8px', 
            padding: '14px', 
            fontFamily: 'var(--font-mono)', 
            fontSize: '0.78rem', 
            maxHeight: '220px', 
            overflowY: 'auto',
            display: 'flex',
            flexDirection: 'column',
            gap: '6px'
          }}>
            {restoreLogs.map((log, idx) => (
              <div key={idx} style={{ color: log.success !== false ? '#10b981' : 'var(--color-red)' }}>
                <span style={{ color: 'var(--text-dark)', marginRight: '8px' }}>[{new Date(log.timestamp).toLocaleTimeString()}]</span>
                {log.msg}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
