import React, { useState } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  Lock, 
  CheckCircle, 
  AlertTriangle, 
  Layers, 
  Cpu, 
  Archive, 
  Trash2, 
  Eye, 
  Play, 
  Terminal, 
  Copy, 
  Check, 
  FileText, 
  Folder, 
  RefreshCw, 
  X, 
  CheckSquare, 
  Square,
  HardDrive
} from 'lucide-react';
import api from '../api';

const consoleTrans = {
  es: {
    title: "ESCUDO DE EMERGENCIA / NUCLEAR DEFENSE",
    subtitle: "Protección criptográfica inmediata de archivos confidenciales ante incidentes de seguridad o accesos no autorizados.",
    targetsCount: "Rutas Objetivo",
    algoTitle: "Algoritmo de Blindaje",
    backupTitle: "Copia de Seguridad",
    backupActive: "Activa (Verificada SHA3)",
    backupBypassed: "Desactivada",
    shredTitle: "Modo de Destrucción",
    shredActive: "Triturador Activo (Shredding)",
    shredSafe: "No Destructivo (Originales Seguros)",
    scanBtn: "Escanear y Previsualizar Archivos",
    scanning: "Escaneando rutas...",
    executeBtn: "EJECUTAR ESCUDO DE EMERGENCIA",
    executing: "EJECUTANDO PROTOCOLO DEFENSIVO...",
    modalTitle: "CONFIRMACIÓN DE PROTOCOLO DE EMERGENCIA",
    modalSubtitle: "Verifica los detalles antes de sellar los archivos en el Vault blindado.",
    summaryFiles: "Archivos a Proteger:",
    summarySize: "Tamaño Total:",
    summaryAlgo: "Algoritmo:",
    summaryVault: "Destino del Vault:",
    summaryBackup: "Copia de Respaldo:",
    dangerBanner: "⚠️ ADVERTENCIA CRÍTICA: La opción de destrucción segura de archivos originales está ACTIVADA. Tras el empaquetado, los archivos originales se sobrescribirán físicamente.",
    checkLabel: "He revisado la previsualización y autorizo el blindaje criptográfico de los archivos seleccionados.",
    typePrompt: "Para confirmar, escribe la palabra CONFIRMAR a continuación:",
    confirmKeywordPlaceholder: "Escribe CONFIRMAR aquí...",
    cancelBtn: "Cancelar",
    confirmExecuteBtn: "Confirmar y Ejecutar Blindaje",
    previewTitle: "PREVISUALIZACIÓN DE ARCHIVOS OBJETIVO",
    colName: "Archivo",
    colRelPath: "Ruta Relativa",
    colSize: "Tamaño",
    colStatus: "Estado",
    statusIncluded: "A Proteger",
    noFilesFound: "No se encontraron archivos en las rutas configuradas. Revisa la pestaña de Configuración.",
    closeBtn: "Cerrar",
    terminalTitle: "REGISTRO DE AUDITORÍA EN TIEMPO REAL",
    successTitle: "¡ESCUDO DE EMERGENCIA EJECUTADO EXITOSAMENTE!",
    successDesc: "Los archivos han sido empaquetados, blindados y verificados criptográficamente.",
    vaultGenerated: "Vault Cifrado Generado:",
    vaultHash: "Hash SHA3-256 del Vault:",
    backupGenerated: "Copia de Seguridad Generada:",
    filesProtected: "Archivos Protegidos:",
    shreddedCount: "Archivos Originales Triturados:",
    copy: "Copiar",
    copied: "¡Copiado!",
    passRequiredError: "Debes configurar la Contraseña Maestra en la pestaña de Configuración antes de ejecutar."
  },
  en: {
    title: "EMERGENCY SHIELD / NUCLEAR DEFENSE",
    subtitle: "Immediate cryptographic shielding of confidential assets in response to security incidents or unauthorized intrusions.",
    targetsCount: "Target Paths",
    algoTitle: "Armoring Algorithm",
    backupTitle: "Safety Backup",
    backupActive: "Active (SHA3 Verified)",
    backupBypassed: "Bypassed",
    shredTitle: "Destruction Mode",
    shredActive: "Active Shredder (Wiping)",
    shredSafe: "Non-Destructive (Originals Safe)",
    scanBtn: "Scan & Preview Files",
    scanning: "Scanning paths...",
    executeBtn: "EXECUTE EMERGENCY DEFENSE",
    executing: "EXECUTING DEFENSE PROTOCOL...",
    modalTitle: "EMERGENCY PROTOCOL CONFIRMATION",
    modalSubtitle: "Verify operation parameters before sealing files into the armored Vault.",
    summaryFiles: "Files to Protect:",
    summarySize: "Total Volume:",
    summaryAlgo: "Algorithm:",
    summaryVault: "Vault Output:",
    summaryBackup: "Safety Backup:",
    dangerBanner: "⚠️ CRITICAL WARNING: Original file shredder is ENABLED. Original files will be physically overwritten on disk after vault sealing.",
    checkLabel: "I have reviewed the pre-flight scan and authorize cryptographic armoring of selected files.",
    typePrompt: "To confirm, please type CONFIRMAR or PROTECT below:",
    confirmKeywordPlaceholder: "Type CONFIRMAR or PROTECT...",
    cancelBtn: "Cancel",
    confirmExecuteBtn: "Confirm & Arm Shield",
    previewTitle: "TARGET FILES PRE-FLIGHT PREVIEW",
    colName: "File",
    colRelPath: "Relative Path",
    colSize: "Size",
    colStatus: "Status",
    statusIncluded: "To Protect",
    noFilesFound: "No matching files found in configured paths. Please check the Configuration tab.",
    closeBtn: "Close",
    terminalTitle: "REAL-TIME AUDIT LOG TERMINAL",
    successTitle: "EMERGENCY SHIELD EXECUTED SUCCESSFULLY!",
    successDesc: "All target assets have been packaged, armored, and verified cryptographically.",
    vaultGenerated: "Armored Vault Created:",
    vaultHash: "Vault SHA3-256 Hash:",
    backupGenerated: "Safety Backup Created:",
    filesProtected: "Files Protected:",
    shreddedCount: "Original Files Shredded:",
    copy: "Copy",
    copied: "Copied!",
    passRequiredError: "You must configure the Master Emergency Password in the Configuration tab before execution."
  }
};

export default function EmergencyConsole({ 
  config, 
  password, 
  doubleFactorPassword,
  onNavigateToConfig,
  lang = 'es' 
}) {
  const t = consoleTrans[lang] || consoleTrans.es;

  // States
  const [isScanning, setIsScanning] = useState(false);
  const [scanData, setScanData] = useState(null);
  const [showPreviewModal, setShowPreviewModal] = useState(false);
  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const [isExecuting, setIsExecuting] = useState(false);
  const [execLogs, setExecLogs] = useState([]);
  const [execResult, setExecResult] = useState(null);
  const [errorMessage, setErrorMessage] = useState('');

  // Confirmation modal states
  const [confirmChecked, setConfirmChecked] = useState(false);
  const [confirmKeyword, setConfirmKeyword] = useState('');
  const [copiedField, setCopiedField] = useState(null);

  const copyToClipboard = (text, id) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedField(id);
    setTimeout(() => setCopiedField(null), 1500);
  };

  // Pre-flight scan
  const handleScan = async () => {
    setIsScanning(true);
    setErrorMessage('');
    try {
      const data = await api.scanEmergency({
        targetPaths: config.targetPaths || [],
        exclusions: config.exclusions || []
      });
      if (data && data.success) {
        setScanData(data);
        setShowPreviewModal(true);
      } else {
        setErrorMessage(data?.error || 'Scan failed');
      }
    } catch (err) {
      setErrorMessage(err.message);
    } finally {
      setIsScanning(false);
    }
  };

  // Open confirmation modal
  const handleOpenConfirm = async () => {
    setErrorMessage('');
    if (!password || password.length < 10) {
      setErrorMessage(t.passRequiredError);
      return;
    }

    // Auto scan if not yet done
    if (!scanData) {
      setIsScanning(true);
      try {
        const data = await api.scanEmergency({
          targetPaths: config.targetPaths || [],
          exclusions: config.exclusions || []
        });
        if (data && data.success) {
          setScanData(data);
        } else {
          setErrorMessage(data?.error || 'Scan failed');
          setIsScanning(false);
          return;
        }
      } catch (e) {
        setErrorMessage(e.message);
        setIsScanning(false);
        return;
      }
      setIsScanning(false);
    }

    setConfirmChecked(false);
    setConfirmKeyword('');
    setShowConfirmModal(true);
  };

  // Execute Nuclear Protocol
  const handleExecute = async () => {
    setShowConfirmModal(false);
    setIsExecuting(true);
    setExecLogs([]);
    setExecResult(null);
    setErrorMessage('');

    try {
      const data = await api.executeEmergency({
        password,
        secondFactor: doubleFactorPassword || '',
        targets: config.targetPaths || [],
        exclusions: config.exclusions || [],
        algorithm: config.algorithm || 'mirage-c4',
        outputPath: config.outputPath,
        backupEnabled: config.backupEnabled !== false,
        backupPath: config.backupPath,
        shredAfter: !!config.shredOriginalEnabled,
        shredPasses: config.shredPasses || 3,
        hardwareLock: !!config.hardwareLockEnabled,
        metadataScrubEnabled: config.metadataScrubEnabled !== false,
        sizeObfuscationEnabled: config.sizeObfuscationEnabled !== false,
        ttlEnabled: !!config.ttlEnabled,
        ttlValue: config.ttlValue || '0',
        confirmationKeyword: confirmKeyword
      });

      if (data && data.steps) {
        setExecLogs(data.steps);
      }
      if (data && data.success) {
        setExecResult(data);
      } else {
        setErrorMessage(data?.error || 'Emergency operation failed');
      }
    } catch (err) {
      setErrorMessage(err.message);
    } finally {
      setIsExecuting(false);
    }
  };

  const isConfirmationValid = () => {
    if (!confirmChecked) return false;
    if (config.shredOriginalEnabled) {
      const clean = confirmKeyword.trim().toUpperCase();
      return clean === 'CONFIRMAR' || clean === 'PROTECT';
    }
    return true;
  };

  return (
    <div className="emergency-console-container animate-fade-in">
      {/* HEADER */}
      <div className="section-header" style={{ marginBottom: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div className="status-indicator-icon pulse-glow" style={{ background: 'rgba(239, 68, 68, 0.2)', border: '1px solid var(--color-red)' }}>
            <ShieldAlert size={26} style={{ color: 'var(--color-red)' }} />
          </div>
          <div>
            <h2 className="brand-title" style={{ fontSize: '1.4rem', color: 'var(--color-red)' }}>{t.title}</h2>
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

      {/* STATUS OVERVIEW CARDS */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px', marginBottom: '24px' }}>
        <div className="dashboard-card" style={{ padding: '16px', display: 'flex', alignItems: 'center', gap: '12px' }}>
          <Folder size={24} style={{ color: 'var(--color-primary)' }} />
          <div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{t.targetsCount}</div>
            <div style={{ fontSize: '1.2rem', fontFamily: 'var(--font-orbitron)', fontWeight: 600 }}>
              {(config.targetPaths || []).length}
            </div>
          </div>
        </div>

        <div className="dashboard-card" style={{ padding: '16px', display: 'flex', alignItems: 'center', gap: '12px' }}>
          <Layers size={24} style={{ color: 'var(--color-cyan)' }} />
          <div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{t.algoTitle}</div>
            <div style={{ fontSize: '0.95rem', fontFamily: 'var(--font-orbitron)', fontWeight: 600, color: 'var(--color-cyan)' }}>
              {config.algorithm === 'mirage-c4' ? 'MIRAGE-C4 (4×256-bit)' : 'AES-256-GCM'}
            </div>
          </div>
        </div>

        <div className="dashboard-card" style={{ padding: '16px', display: 'flex', alignItems: 'center', gap: '12px' }}>
          <Archive size={24} style={{ color: config.backupEnabled ? 'var(--color-green)' : 'var(--text-muted)' }} />
          <div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{t.backupTitle}</div>
            <div style={{ fontSize: '0.85rem', fontWeight: 600, color: config.backupEnabled ? 'var(--color-green)' : 'var(--text-muted)' }}>
              {config.backupEnabled ? t.backupActive : t.backupBypassed}
            </div>
          </div>
        </div>

        <div className="dashboard-card" style={{ padding: '16px', display: 'flex', alignItems: 'center', gap: '12px' }}>
          <Trash2 size={24} style={{ color: config.shredOriginalEnabled ? 'var(--color-red)' : 'var(--color-green)' }} />
          <div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{t.shredTitle}</div>
            <div style={{ fontSize: '0.85rem', fontWeight: 600, color: config.shredOriginalEnabled ? 'var(--color-red)' : 'var(--color-green)' }}>
              {config.shredOriginalEnabled ? t.shredActive : t.shredSafe}
            </div>
          </div>
        </div>
      </div>

      {/* ACTION TRIGGERS */}
      <div className="dashboard-card" style={{ marginBottom: '24px', padding: '24px', textAlign: 'center', background: 'radial-gradient(ellipse at center, rgba(239, 68, 68, 0.08) 0%, rgba(18, 14, 30, 0.7) 100%)' }}>
        <div style={{ display: 'flex', justifyContent: 'center', gap: '16px', flexWrap: 'wrap' }}>
          <button
            type="button"
            className="btn-secondary"
            onClick={handleScan}
            disabled={isScanning || isExecuting}
            style={{ padding: '12px 24px', fontSize: '0.9rem' }}
          >
            {isScanning ? <RefreshCw className="spin" size={18} /> : <Eye size={18} />}
            {isScanning ? t.scanning : t.scanBtn}
          </button>

          <button
            type="button"
            className="btn-danger pulse-glow"
            onClick={handleOpenConfirm}
            disabled={isScanning || isExecuting}
            style={{ 
              padding: '14px 32px', 
              fontSize: '1rem', 
              fontFamily: 'var(--font-orbitron)', 
              letterSpacing: '1px',
              background: 'linear-gradient(135deg, #ef4444 0%, #b91c1c 100%)',
              boxShadow: '0 0 25px rgba(239, 68, 68, 0.5)'
            }}
          >
            <ShieldAlert size={20} />
            {isExecuting ? t.executing : t.executeBtn}
          </button>
        </div>
      </div>

      {/* SUCCESS RESULT SCREEN */}
      {execResult && (
        <div className="dashboard-card animate-fade-in" style={{ marginBottom: '24px', border: '1px solid var(--color-green)', background: 'rgba(16, 185, 129, 0.05)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
            <CheckCircle size={28} style={{ color: 'var(--color-green)' }} />
            <div>
              <h3 style={{ fontFamily: 'var(--font-orbitron)', fontSize: '1.1rem', color: 'var(--color-green)' }}>{t.successTitle}</h3>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>{t.successDesc}</p>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">{t.vaultGenerated}</label>
              <div className="form-input-wrapper">
                <Archive className="form-input-icon" size={16} />
                <input type="text" className="form-input" value={execResult.vaultPath || ''} readOnly />
                <button type="button" className="btn-icon" onClick={() => copyToClipboard(execResult.vaultPath, 'vaultPath')}>
                  {copiedField === 'vaultPath' ? <Check size={16} /> : <Copy size={16} />}
                </button>
              </div>
            </div>

            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">{t.vaultHash}</label>
              <div className="form-input-wrapper">
                <Shield className="form-input-icon" size={16} />
                <input type="text" className="form-input" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }} value={execResult.vaultHash || ''} readOnly />
                <button type="button" className="btn-icon" onClick={() => copyToClipboard(execResult.vaultHash, 'vaultHash')}>
                  {copiedField === 'vaultHash' ? <Check size={16} /> : <Copy size={16} />}
                </button>
              </div>
            </div>

            {execResult.backupPath && (
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label className="form-label">{t.backupGenerated}</label>
                <div className="form-input-wrapper">
                  <Folder className="form-input-icon" size={16} />
                  <input type="text" className="form-input" value={execResult.backupPath || ''} readOnly />
                  <button type="button" className="btn-icon" onClick={() => copyToClipboard(execResult.backupPath, 'backupPath')}>
                    {copiedField === 'backupPath' ? <Check size={16} /> : <Copy size={16} />}
                  </button>
                </div>
              </div>
            )}

            <div style={{ display: 'flex', gap: '20px', fontSize: '0.85rem', marginTop: '6px' }}>
              <div><strong>{t.filesProtected}</strong> {execResult.fileCount} ({(execResult.totalBytes / (1024 * 1024)).toFixed(2)} MB)</div>
              {execResult.shreddedCount > 0 && (
                <div style={{ color: 'var(--color-red)' }}><strong>{t.shreddedCount}</strong> {execResult.shreddedCount}</div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* REAL-TIME LOG TERMINAL */}
      {(execLogs.length > 0 || isExecuting) && (
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
            maxHeight: '260px', 
            overflowY: 'auto',
            display: 'flex',
            flexDirection: 'column',
            gap: '6px'
          }}>
            {execLogs.map((log, idx) => (
              <div key={idx} style={{ color: log.success !== false ? (log.msg.includes('ERROR') ? 'var(--color-red)' : '#10b981') : 'var(--color-red)' }}>
                <span style={{ color: 'var(--text-dark)', marginRight: '8px' }}>[{new Date(log.timestamp).toLocaleTimeString()}]</span>
                {log.msg}
              </div>
            ))}
            {isExecuting && (
              <div style={{ color: 'var(--color-cyan)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <RefreshCw size={14} className="spin" />
                <span>{t.executing}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* MODAL 1: PRE-FLIGHT PREVIEW MODAL */}
      {showPreviewModal && (
        <div className="modal-backdrop animate-fade-in" style={{ position: 'fixed', top: 0, left: 0, width: '100%', height: '100%', background: 'rgba(0,0,0,0.8)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000, padding: '20px' }}>
          <div className="modal-card" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '12px', width: '100%', maxWidth: '750px', maxHeight: '85vh', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
            <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Eye size={20} style={{ color: 'var(--color-cyan)' }} />
                <h3 style={{ fontFamily: 'var(--font-orbitron)', fontSize: '1rem' }}>{t.previewTitle}</h3>
              </div>
              <button type="button" className="btn-icon" onClick={() => setShowPreviewModal(false)}>
                <X size={18} />
              </button>
            </div>

            <div style={{ padding: '16px 20px', overflowY: 'auto', flex: 1 }}>
              {scanData && scanData.files && scanData.files.length > 0 ? (
                <div>
                  <div style={{ display: 'flex', gap: '20px', marginBottom: '14px', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                    <span><strong>Total:</strong> {scanData.totalCount} archivos ({(scanData.totalBytes / (1024 * 1024)).toFixed(2)} MB)</span>
                    <span><strong>Excluidos:</strong> {scanData.excludedCount}</span>
                    <span><strong>Protegidos por SO:</strong> {scanData.systemProtectedCount}</span>
                  </div>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem', textAlign: 'left' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid var(--border)', color: 'var(--text-muted)' }}>
                        <th style={{ padding: '8px' }}>{t.colName}</th>
                        <th style={{ padding: '8px' }}>{t.colRelPath}</th>
                        <th style={{ padding: '8px' }}>{t.colSize}</th>
                        <th style={{ padding: '8px' }}>{t.colStatus}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scanData.files.map((file, i) => (
                        <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                          <td style={{ padding: '8px', fontWeight: 500 }}>{file.name}</td>
                          <td style={{ padding: '8px', fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-muted)' }}>{file.relPath}</td>
                          <td style={{ padding: '8px', whiteSpace: 'nowrap' }}>{(file.size / 1024).toFixed(1)} KB</td>
                          <td style={{ padding: '8px' }}>
                            <span style={{ padding: '2px 6px', background: 'rgba(16, 185, 129, 0.1)', color: 'var(--color-green)', borderRadius: '4px', fontSize: '0.7rem' }}>
                              {t.statusIncluded}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)', fontSize: '0.9rem' }}>
                  {t.noFilesFound}
                </div>
              )}
            </div>

            <div style={{ padding: '14px 20px', borderTop: '1px solid var(--border)', display: 'flex', justifyContent: 'flex-end' }}>
              <button type="button" className="btn-secondary" onClick={() => setShowPreviewModal(false)}>
                {t.closeBtn}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL 2: EXPLICIT DOUBLE CONFIRMATION MODAL */}
      {showConfirmModal && (
        <div className="modal-backdrop animate-fade-in" style={{ position: 'fixed', top: 0, left: 0, width: '100%', height: '100%', background: 'rgba(0,0,0,0.85)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000, padding: '20px' }}>
          <div className="modal-card" style={{ background: 'var(--bg-card)', border: '1px solid var(--color-red)', borderRadius: '12px', width: '100%', maxWidth: '620px', display: 'flex', flexDirection: 'column', overflow: 'hidden', boxShadow: '0 0 40px rgba(239, 68, 68, 0.3)' }}>
            <div style={{ padding: '18px 24px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: '12px' }}>
              <ShieldAlert size={26} style={{ color: 'var(--color-red)' }} />
              <div>
                <h3 style={{ fontFamily: 'var(--font-orbitron)', fontSize: '1.1rem', color: 'var(--color-red)' }}>{t.modalTitle}</h3>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{t.modalSubtitle}</p>
              </div>
            </div>

            <div style={{ padding: '20px 24px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
              {config.shredOriginalEnabled && (
                <div style={{ padding: '12px 16px', background: 'rgba(239, 68, 68, 0.15)', border: '1px solid var(--color-red)', borderRadius: '8px', color: 'var(--color-red)', fontSize: '0.85rem', lineHeight: 1.4 }}>
                  {t.dangerBanner}
                </div>
              )}

              <div style={{ background: 'var(--bg-panel)', padding: '14px', borderRadius: '8px', fontSize: '0.85rem', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <div><strong>{t.summaryFiles}</strong> {scanData ? scanData.totalCount : '0'} ({(scanData ? scanData.totalBytes / (1024 * 1024) : 0).toFixed(2)} MB)</div>
                <div><strong>{t.summaryAlgo}</strong> {config.algorithm === 'mirage-c4' ? 'MIRAGE-C4 (4×256-bit Cascade)' : 'AES-256-GCM'}</div>
                <div><strong>{t.summaryBackup}</strong> {config.backupEnabled ? t.backupActive : t.backupBypassed}</div>
                <div><strong>{t.summaryVault}</strong> {config.outputPath || 'Default'}</div>
              </div>

              {/* Checkbox verification */}
              <div 
                style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', marginTop: '6px' }}
                onClick={() => setConfirmChecked(!confirmChecked)}
              >
                {confirmChecked ? (
                  <CheckSquare size={20} style={{ color: 'var(--color-primary)', flexShrink: 0, marginTop: '2px' }} />
                ) : (
                  <Square size={20} style={{ color: 'var(--text-muted)', flexShrink: 0, marginTop: '2px' }} />
                )}
                <span style={{ fontSize: '0.85rem', lineHeight: 1.4 }}>{t.checkLabel}</span>
              </div>

              {/* Text confirmation prompt */}
              {config.shredOriginalEnabled && (
                <div className="form-group" style={{ marginBottom: 0, marginTop: '8px' }}>
                  <label className="form-label" style={{ color: 'var(--color-red)', fontSize: '0.8rem' }}>{t.typePrompt}</label>
                  <input
                    type="text"
                    className="form-input"
                    value={confirmKeyword}
                    onChange={(e) => setConfirmKeyword(e.target.value)}
                    placeholder={t.confirmKeywordPlaceholder}
                    style={{ borderColor: isConfirmationValid() ? 'var(--color-green)' : 'var(--color-red)' }}
                  />
                </div>
              )}
            </div>

            <div style={{ padding: '16px 24px', borderTop: '1px solid var(--border)', display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
              <button type="button" className="btn-secondary" onClick={() => setShowConfirmModal(false)}>
                {t.cancelBtn}
              </button>
              <button
                type="button"
                className="btn-danger"
                onClick={handleExecute}
                disabled={!isConfirmationValid()}
                style={{ opacity: isConfirmationValid() ? 1 : 0.4 }}
              >
                <ShieldAlert size={18} /> {t.confirmExecuteBtn}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
