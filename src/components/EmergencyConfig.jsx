import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Lock, 
  Cpu, 
  Key, 
  Trash2, 
  FolderPlus, 
  FileText, 
  Layers, 
  Archive, 
  AlertTriangle, 
  CheckCircle, 
  Plus, 
  X, 
  Save, 
  Eye, 
  EyeOff, 
  Folder, 
  Info,
  ShieldAlert,
  Clock,
  Shuffle,
  Zap,
  Sparkles,
  Sliders,
  Check
} from 'lucide-react';
import PathInput from './PathInput';
import api from '../api';

const configTrans = {
  es: {
    title: "CENTRO DE CONFIGURACIÓN DE EMERGENCIA",
    subtitle: "Configura objetivos, exclusiones, algoritmo MIRAGE-C4 y salvaguardas defensivas para el Escudo Nuclear.",
    tabs: {
      targets: "1. Rutas y Objetivos",
      exclusions: "2. Filtros de Exclusión",
      crypto: "3. Criptografía & Vault",
      safeguards: "4. Salvaguardas & Respaldos",
      keys: "5. Clave & Recuperación"
    },
    presetsTitle: "Perfiles de Configuración Rápida",
    presetMax: "Máxima Seguridad (Paranoid)",
    presetDocs: "Documentos & Finanzas",
    presetFast: "Cifrado Rápido",
    presetApplied: "Perfil aplicado:",
    sectionTargets: "Rutas y Carpetas Objetivo a Proteger",
    targetsDesc: "Agrega las carpetas o archivos confidenciales que serán empaquetados y blindados en caso de emergencia.",
    addTargetBtn: "+ Agregar Ruta Objetivo",
    targetPlaceholder: "Ej: C:\\Users\\Usuario\\Documents\\Finanzas",
    quickFolders: "Accesos Rápidos a Carpetas Comunes:",
    noTargets: "No hay rutas configuradas. Agrega al menos una carpeta o archivo para proteger.",
    sectionExclusions: "Filtros y Reglas de Exclusión",
    exclusionsDesc: "Archivos o patrones que serán ignorados durante el escaneo de emergencia.",
    addExclusionBtn: "+ Agregar Exclusión",
    exclusionPlaceholder: "Ej: .tmp, .log, .git, node_modules",
    presetFiltersTitle: "Filtros Predefinidos Recomendados:",
    presetDev: "+ Desarrollo (.git, node_modules, .env)",
    presetTemp: "+ Temporales (.tmp, .log, .bak)",
    presetSystem: "+ Sistema (desktop.ini, thumbs.db)",
    sectionCrypto: "Motor Criptográfico y Vault de Salida",
    algoLabel: "Algoritmo de Cifrado",
    c4Option: "MIRAGE-C4 (Cascada de 4 Capas 4×256-bit: Camellia + ARIA + ChaCha20 + AES-GCM) [Recomendado]",
    aesOption: "AES-256-GCM (Estándar Militar Autenticado de 256 bits)",
    c4DiagramTitle: "Arquitectura de Cascada C4 (4 Capas Secuenciales):",
    c4Layer1: "Capa 1: Camellia-256-CTR",
    c4Layer2: "Capa 2: ARIA-256-CTR",
    c4Layer3: "Capa 3: ChaCha20 Stream",
    c4Layer4: "Capa 4: AES-256-GCM (Autenticación AEAD 128-bit)",
    outputPathLabel: "Directorio de Salida del Vault de Emergencia",
    outputPathPlaceholder: "Ej: C:\\Users\\Usuario\\MirageVault",
    sectionSafety: "Salvaguardas de Seguridad y Copias Previas",
    backupTitle: "Copia de Respaldo de Seguridad Previa (Verificada SHA3)",
    backupDesc: "Genera una copia de seguridad empaquetada antes de cualquier modificación y verifica su integridad.",
    backupPathLabel: "Directorio de Almacenamiento de Respaldos",
    backupPathPlaceholder: "Ej: C:\\Users\\Usuario\\MirageBackups",
    shredTitle: "Destrucción Segura de Archivos Originales (Shredder)",
    shredDesc: "Sobrescribe físicamente los archivos originales en disco en múltiples pasadas tras cifrarlos en el Vault.",
    shredWarning: "⚠️ ADVERTENCIA: Esta acción es IRREVERSIBLE. Los archivos originales serán eliminados permanentemente del disco físico tras empaquetarse en el Vault cifrado.",
    shredPassesLabel: "Pasadas de Sobrescritura",
    shredPass1: "1 pasada (Rápido - Ruido aleatorio)",
    shredPass3: "3 pasadas (Estándar Seguro DoD)",
    shredPass7: "7 pasadas (Sobrescritura Gutmann / Militar)",
    sectionKey: "Clave Maestra y Kit de Recuperación",
    keyDesc: "Contraseña con la que se derivarán las claves Scrypt para sellar y recuperar el Vault.",
    passLabel: "Contraseña Maestra de Emergencia",
    passPlaceholder: "Ingresa una contraseña segura (mínimo 10 caracteres)...",
    generatePassBtn: "Generar Clave Aleatoria Fuerte",
    dfPassLabel: "Segundo Secreto / 2FA Password (Opcional)",
    dfPassPlaceholder: "Contraseña complementaria opcional...",
    hwLockTitle: "Bloqueo Criptográfico por Hardware (UUID)",
    hwLockDesc: "Vincula el descifrado a este equipo físico exacto mediante su identificador de placa base/CPU.",
    metaScrubTitle: "Depuración de Metadatos (EXIF/GPS)",
    metaScrubDesc: "Elimina etiquetas de geolocalización y autor en imágenes JPEG y PNG.",
    sizeObfTitle: "Ofuscación de Tamaño (Signal-style Padding)",
    sizeObfDesc: "Agrega ruido de bytes aleatorios para ocultar el peso real del contenedor.",
    ttlTitle: "Tiempo de Expiración del Vault (TTL)",
    ttlDesc: "El vault se auto-destruirá criptográficamente tras el tiempo indicado (en horas). 0 = Sin límite.",
    saveBtn: "Guardar Configuración de Emergencia",
    saving: "Guardando...",
    savedSuccess: "✓ ¡Configuración de emergencia guardada exitosamente!",
    errorSaving: "Error al guardar la configuración:",
    remove: "Eliminar"
  },
  en: {
    title: "EMERGENCY DEFENSE CONFIGURATION CENTER",
    subtitle: "Configure target paths, exclusions, core algorithm, and safeguards before arming the Nuclear Shield.",
    tabs: {
      targets: "1. Target Vaults",
      exclusions: "2. Exclusions",
      crypto: "3. Crypto & Vault",
      safeguards: "4. Safeguards & Backups",
      keys: "5. Keys & Recovery"
    },
    presetsTitle: "Quick Configuration Profiles",
    presetMax: "Max Security (Paranoid)",
    presetDocs: "Documents & Finance",
    presetFast: "Fast Encryption",
    presetApplied: "Profile applied:",
    sectionTargets: "Target Folders & Files to Protect",
    targetsDesc: "Add confidential folders or files that will be packaged and shielded during an emergency.",
    addTargetBtn: "+ Add Target Path",
    targetPlaceholder: "E.g., C:\\Users\\User\\Documents\\Financial",
    quickFolders: "Quick Shortcuts to Common Folders:",
    noTargets: "No target paths configured. Add at least one folder or file.",
    sectionExclusions: "Exclusion Rules & Filters",
    exclusionsDesc: "File extensions or patterns to ignore during emergency scanning.",
    addExclusionBtn: "+ Add Exclusion",
    exclusionPlaceholder: "E.g., .tmp, .log, .git, node_modules",
    presetFiltersTitle: "Recommended Preset Filters:",
    presetDev: "+ Dev (.git, node_modules, .env)",
    presetTemp: "+ Temp (.tmp, .log, .bak)",
    presetSystem: "+ System (desktop.ini, thumbs.db)",
    sectionCrypto: "Cryptographic Core & Output Vault",
    algoLabel: "Encryption Algorithm",
    c4Option: "MIRAGE-C4 (4-Layer 4×256-bit Cascade: Camellia + ARIA + ChaCha20 + AES-GCM) [Recommended]",
    aesOption: "AES-256-GCM (256-bit Military Authenticated Standard)",
    c4DiagramTitle: "Mirage-C4 Cascade Architecture (4 Sequential Layers):",
    c4Layer1: "Layer 1: Camellia-256-CTR",
    c4Layer2: "Layer 2: ARIA-256-CTR",
    c4Layer3: "Layer 3: ChaCha20 Stream",
    c4Layer4: "Layer 4: AES-256-GCM (128-bit AEAD Authentication)",
    outputPathLabel: "Emergency Vault Output Directory",
    outputPathPlaceholder: "E.g., C:\\Users\\User\\MirageVault",
    sectionSafety: "Safety Safeguards & Backup Verification",
    backupTitle: "Pre-execution Safety Backup (SHA3 Verified)",
    backupDesc: "Generates an unencrypted safety backup archive before any operation and verifies integrity.",
    backupPathLabel: "Backup Storage Directory",
    backupPathPlaceholder: "E.g., C:\\Users\\User\\MirageBackups",
    shredTitle: "Secure Shredder (Original File Wiping)",
    shredDesc: "Physically overwrites original files on disk with random passes after packaging into the Vault.",
    shredWarning: "⚠️ WARNING: This action is IRREVERSIBLE. Original files will be permanently wiped from disk after being encapsulated into the encrypted Vault.",
    shredPassesLabel: "Overwrite Passes",
    shredPass1: "1 pass (Fast - Random noise)",
    shredPass3: "3 passes (Secure Standard DoD)",
    shredPass7: "7 passes (Deep Military / Gutmann)",
    sectionKey: "Master Key & Recovery Kit",
    keyDesc: "Master password used to derive Scrypt keys to seal and restore the Vault.",
    passLabel: "Master Emergency Password",
    passPlaceholder: "Enter strong password (minimum 10 characters)...",
    generatePassBtn: "Generate Strong Random Password",
    dfPassLabel: "Secondary Secret / 2FA Password (Optional)",
    dfPassPlaceholder: "Optional secondary secret...",
    hwLockTitle: "Hardware Pepper Lock (UUID Binding)",
    hwLockDesc: "Binds decryption strictly to this physical computer motherboard UUID.",
    metaScrubTitle: "Metadata Scrubbing (EXIF/GPS)",
    metaScrubDesc: "Removes author and GPS tags from JPEG/PNG images prior to armoring.",
    sizeObfTitle: "Size Obfuscation (Signal-style Padding)",
    sizeObfDesc: "Appends exponential random noise bytes to conceal actual container size.",
    ttlTitle: "Vault Time-to-Live (TTL)",
    ttlDesc: "Vault auto-expires and self-destructs after configured hours. 0 = Unlimited.",
    saveBtn: "Save Emergency Configuration",
    saving: "Saving...",
    savedSuccess: "✓ Emergency configuration saved successfully!",
    errorSaving: "Failed to save configuration:",
    remove: "Remove"
  }
};

export default function EmergencyConfig({ 
  config, 
  setConfig, 
  password, 
  setPassword, 
  doubleFactorPassword, 
  setDoubleFactorPassword,
  lang = 'es' 
}) {
  const t = configTrans[lang] || configTrans.es;
  const [activeTab, setActiveTab] = useState('targets');
  const [saveStatus, setSaveStatus] = useState(null);
  const [isSaving, setIsSaving] = useState(false);
  const [showPass, setShowPass] = useState(false);
  const [showDfPass, setShowDfPass] = useState(false);
  const [newExclusion, setNewExclusion] = useState('');
  const [systemShortcuts, setSystemShortcuts] = useState([]);

  useEffect(() => {
    api.getShortcuts()
      .then(data => {
        if (data && data.shortcuts) setSystemShortcuts(data.shortcuts);
      })
      .catch(e => {});
  }, []);

  const applyPreset = (type) => {
    if (type === 'max') {
      setConfig(prev => ({
        ...prev,
        algorithm: 'mirage-c4',
        backupEnabled: true,
        shredOriginalEnabled: false,
        hardwareLockEnabled: true,
        metadataScrubEnabled: true,
        sizeObfuscationEnabled: true
      }));
      setSaveStatus({ type: 'success', msg: `${t.presetApplied} ${t.presetMax}` });
    } else if (type === 'docs') {
      const docSc = systemShortcuts.find(s => s.name === 'Documentos');
      if (docSc) {
        setConfig(prev => ({
          ...prev,
          targetPaths: Array.from(new Set([...(prev.targetPaths || []), docSc.path])),
          algorithm: 'mirage-c4',
          backupEnabled: true
        }));
      }
      setSaveStatus({ type: 'success', msg: `${t.presetApplied} ${t.presetDocs}` });
    } else if (type === 'fast') {
      setConfig(prev => ({
        ...prev,
        algorithm: 'aes-256-gcm',
        backupEnabled: true,
        shredOriginalEnabled: false,
        sizeObfuscationEnabled: false
      }));
      setSaveStatus({ type: 'success', msg: `${t.presetApplied} ${t.presetFast}` });
    }
    setTimeout(() => setSaveStatus(null), 3000);
  };

  const generateStrongPassword = () => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+~|}{[]:;?><,./-=';
    let res = '';
    const array = new Uint32Array(24);
    window.crypto.getRandomValues(array);
    for (let i = 0; i < 24; i++) {
      res += chars[array[i] % chars.length];
    }
    setPassword(res);
    setShowPass(true);
  };

  const addTargetPath = () => {
    setConfig(prev => ({
      ...prev,
      targetPaths: [...(prev.targetPaths || []), '']
    }));
  };

  const addQuickShortcut = (scPath) => {
    if (!config.targetPaths?.includes(scPath)) {
      setConfig(prev => ({
        ...prev,
        targetPaths: [...(prev.targetPaths || []).filter(Boolean), scPath]
      }));
    }
  };

  const updateTargetPath = (index, value) => {
    setConfig(prev => {
      const updated = [...(prev.targetPaths || [])];
      updated[index] = value;
      return { ...prev, targetPaths: updated };
    });
  };

  const removeTargetPath = (index) => {
    setConfig(prev => ({
      ...prev,
      targetPaths: prev.targetPaths.filter((_, i) => i !== index)
    }));
  };

  const handleAddExclusion = (e) => {
    e.preventDefault();
    if (!newExclusion.trim()) return;
    const clean = newExclusion.trim();
    if (!config.exclusions?.includes(clean)) {
      setConfig(prev => ({
        ...prev,
        exclusions: [...(prev.exclusions || []), clean]
      }));
    }
    setNewExclusion('');
  };

  const addPresetExclusions = (arr) => {
    setConfig(prev => {
      const current = new Set(prev.exclusions || []);
      arr.forEach(item => current.add(item));
      return { ...prev, exclusions: Array.from(current) };
    });
  };

  const removeExclusion = (item) => {
    setConfig(prev => ({
      ...prev,
      exclusions: prev.exclusions.filter(ex => ex !== item)
    }));
  };

  const handleSaveConfig = async () => {
    setIsSaving(true);
    setSaveStatus(null);
    try {
      const data = await api.saveEmergencyConfig(config);
      if (data && data.success) {
        setSaveStatus({ type: 'success', msg: t.savedSuccess });
        setTimeout(() => setSaveStatus(null), 3500);
      } else {
        setSaveStatus({ type: 'error', msg: `${t.errorSaving} ${data?.error || ''}` });
      }
    } catch (err) {
      setSaveStatus({ type: 'error', msg: `${t.errorSaving} ${err.message}` });
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="emergency-config-container animate-fade-in">
      {/* HEADER */}
      <div className="section-header" style={{ marginBottom: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div className="status-indicator-icon pulse-glow" style={{ background: 'rgba(139, 92, 246, 0.2)', border: '1px solid var(--color-primary)' }}>
            <Sliders size={26} style={{ color: 'var(--color-primary)' }} />
          </div>
          <div>
            <h2 className="brand-title" style={{ fontSize: '1.4rem' }}>{t.title}</h2>
            <p className="brand-subtitle" style={{ fontSize: '0.85rem' }}>{t.subtitle}</p>
          </div>
        </div>
      </div>

      {/* QUICK PRESET PROFILES BAR */}
      <div className="dashboard-card" style={{ padding: '14px 18px', marginBottom: '20px', background: 'rgba(255, 255, 255, 0.02)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 600 }}>
            <Zap size={16} style={{ color: 'var(--color-cyan)' }} />
            <span>{t.presetsTitle}:</span>
          </div>
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            <button type="button" className="btn-secondary" onClick={() => applyPreset('max')} style={{ fontSize: '0.75rem', padding: '6px 12px' }}>
              🛡️ {t.presetMax}
            </button>
            <button type="button" className="btn-secondary" onClick={() => applyPreset('docs')} style={{ fontSize: '0.75rem', padding: '6px 12px' }}>
              📁 {t.presetDocs}
            </button>
            <button type="button" className="btn-secondary" onClick={() => applyPreset('fast')} style={{ fontSize: '0.75rem', padding: '6px 12px' }}>
              ⚡ {t.presetFast}
            </button>
          </div>
        </div>
      </div>

      {saveStatus && (
        <div className={`status-banner ${saveStatus.type === 'success' ? 'status-banner-success' : 'status-banner-error'}`} style={{ marginBottom: '20px' }}>
          {saveStatus.type === 'success' ? <CheckCircle size={18} /> : <AlertTriangle size={18} />}
          <span>{saveStatus.msg}</span>
        </div>
      )}

      {/* TAB NAVIGATION PILLS */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '20px', overflowX: 'auto', paddingBottom: '4px' }}>
        {[
          { id: 'targets', label: t.tabs.targets, icon: Folder },
          { id: 'exclusions', label: t.tabs.exclusions, icon: X },
          { id: 'crypto', label: t.tabs.crypto, icon: Layers },
          { id: 'safeguards', label: t.tabs.safeguards, icon: ShieldAlert },
          { id: 'keys', label: t.tabs.keys, icon: Key }
        ].map(tab => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '10px 16px',
                borderRadius: '8px',
                fontSize: '0.85rem',
                fontFamily: 'var(--font-outfit)',
                fontWeight: isActive ? 600 : 400,
                cursor: 'pointer',
                border: isActive ? '1px solid var(--color-primary)' : '1px solid var(--border)',
                background: isActive ? 'rgba(139, 92, 246, 0.18)' : 'rgba(255, 255, 255, 0.02)',
                color: isActive ? 'var(--color-primary)' : 'var(--text-muted)',
                whiteSpace: 'nowrap',
                transition: 'all 0.2s ease'
              }}
            >
              <Icon size={16} />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* TAB CONTENT */}
      {/* 1. TARGETS TAB */}
      {activeTab === 'targets' && (
        <div className="dashboard-card animate-fade-in" style={{ marginBottom: '20px' }}>
          <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
            <div>
              <h3 style={{ fontFamily: 'var(--font-orbitron)', fontSize: '1.05rem', color: 'var(--color-primary)' }}>{t.sectionTargets}</h3>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{t.targetsDesc}</p>
            </div>
            <button type="button" className="btn-secondary" onClick={addTargetPath} style={{ fontSize: '0.8rem', padding: '6px 14px' }}>
              <Plus size={14} /> {t.addTargetBtn}
            </button>
          </div>

          {/* Quick folder shortcuts */}
          {systemShortcuts.length > 0 && (
            <div style={{ marginBottom: '16px', padding: '10px 14px', background: 'var(--bg-panel)', borderRadius: '8px' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '8px' }}>{t.quickFolders}</div>
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                {systemShortcuts.map((sc, i) => (
                  <button
                    key={i}
                    type="button"
                    className="btn-secondary"
                    onClick={() => addQuickShortcut(sc.path)}
                    style={{ fontSize: '0.72rem', padding: '4px 10px', background: 'rgba(255,255,255,0.04)' }}
                  >
                    + {sc.name}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Target List */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {(!config.targetPaths || config.targetPaths.length === 0) ? (
              <div style={{ padding: '20px', background: 'var(--bg-panel)', borderRadius: '8px', border: '1px dashed var(--border)', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                {t.noTargets}
              </div>
            ) : (
              config.targetPaths.map((target, idx) => (
                <div key={idx} style={{ display: 'flex', gap: '10px', alignItems: 'flex-start' }}>
                  <div style={{ flex: 1 }}>
                    <PathInput
                      value={target}
                      onChange={(val) => updateTargetPath(idx, val)}
                      placeholder={t.targetPlaceholder}
                      icon={Folder}
                      mode="directory"
                    />
                  </div>
                  <button
                    type="button"
                    className="btn-danger-outline"
                    onClick={() => removeTargetPath(idx)}
                    title={t.remove}
                    style={{ marginTop: '2px', padding: '11px 12px' }}
                  >
                    <Trash2 size={16} />
                  </button>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* 2. EXCLUSIONS TAB */}
      {activeTab === 'exclusions' && (
        <div className="dashboard-card animate-fade-in" style={{ marginBottom: '20px' }}>
          <div className="card-header" style={{ marginBottom: '14px' }}>
            <h3 style={{ fontFamily: 'var(--font-orbitron)', fontSize: '1.05rem', color: 'var(--color-cyan)' }}>{t.sectionExclusions}</h3>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{t.exclusionsDesc}</p>
          </div>

          {/* Preset filters */}
          <div style={{ marginBottom: '16px', padding: '12px 14px', background: 'var(--bg-panel)', borderRadius: '8px' }}>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '8px' }}>{t.presetFiltersTitle}</div>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              <button
                type="button"
                className="btn-secondary"
                onClick={() => addPresetExclusions(['.git', 'node_modules', '.env', 'build', 'dist'])}
                style={{ fontSize: '0.72rem', padding: '5px 10px' }}
              >
                {t.presetDev}
              </button>
              <button
                type="button"
                className="btn-secondary"
                onClick={() => addPresetExclusions(['.tmp', '.log', '.bak', '.cache'])}
                style={{ fontSize: '0.72rem', padding: '5px 10px' }}
              >
                {t.presetTemp}
              </button>
              <button
                type="button"
                className="btn-secondary"
                onClick={() => addPresetExclusions(['desktop.ini', 'thumbs.db', '.DS_Store'])}
                style={{ fontSize: '0.72rem', padding: '5px 10px' }}
              >
                {t.presetSystem}
              </button>
            </div>
          </div>

          <form onSubmit={handleAddExclusion} style={{ display: 'flex', gap: '10px', marginBottom: '16px' }}>
            <input
              type="text"
              className="form-input"
              value={newExclusion}
              onChange={(e) => setNewExclusion(e.target.value)}
              placeholder={t.exclusionPlaceholder}
              style={{ flex: 1 }}
            />
            <button type="submit" className="btn-secondary" style={{ padding: '0 18px', whiteSpace: 'nowrap' }}>
              <Plus size={16} /> {t.addExclusionBtn}
            </button>
          </form>

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
            {config.exclusions?.map((ex, idx) => (
              <div 
                key={idx} 
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '6px 12px',
                  background: 'rgba(6, 182, 212, 0.1)',
                  border: '1px solid rgba(6, 182, 212, 0.3)',
                  borderRadius: '6px',
                  fontSize: '0.82rem',
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--color-cyan)'
                }}
              >
                <span>{ex}</span>
                <X 
                  size={14} 
                  style={{ cursor: 'pointer', opacity: 0.7 }} 
                  onClick={() => removeExclusion(ex)} 
                />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 3. CRYPTO & VAULT TAB */}
      {activeTab === 'crypto' && (
        <div className="dashboard-card animate-fade-in" style={{ marginBottom: '20px' }}>
          <div className="card-header" style={{ marginBottom: '14px' }}>
            <h3 style={{ fontFamily: 'var(--font-orbitron)', fontSize: '1.05rem', color: 'var(--color-primary)' }}>{t.sectionCrypto}</h3>
          </div>

          <div className="form-group">
            <label className="form-label">{t.algoLabel}</label>
            <select 
              className="form-input" 
              style={{ paddingLeft: '14px' }} 
              value={config.algorithm || 'mirage-c4'}
              onChange={(e) => setConfig(prev => ({ ...prev, algorithm: e.target.value }))}
            >
              <option value="mirage-c4">{t.c4Option}</option>
              <option value="aes-256-gcm">{t.aesOption}</option>
            </select>
          </div>

          {/* Mirage C4 Architecture Visual Diagram */}
          {config.algorithm === 'mirage-c4' && (
            <div style={{ 
              marginBottom: '20px', 
              padding: '16px', 
              background: 'rgba(139, 92, 246, 0.06)', 
              border: '1px solid rgba(139, 92, 246, 0.25)', 
              borderRadius: '8px' 
            }}>
              <div style={{ fontSize: '0.8rem', color: 'var(--color-primary)', fontWeight: 600, marginBottom: '10px' }}>
                {t.c4DiagramTitle}
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '8px', fontSize: '0.75rem' }}>
                <div style={{ padding: '8px 10px', background: 'rgba(0,0,0,0.3)', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.05)' }}>
                  🔹 {t.c4Layer1}
                </div>
                <div style={{ padding: '8px 10px', background: 'rgba(0,0,0,0.3)', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.05)' }}>
                  🔹 {t.c4Layer2}
                </div>
                <div style={{ padding: '8px 10px', background: 'rgba(0,0,0,0.3)', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.05)' }}>
                  🔹 {t.c4Layer3}
                </div>
                <div style={{ padding: '8px 10px', background: 'rgba(0,0,0,0.3)', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.05)' }}>
                  🔒 {t.c4Layer4}
                </div>
              </div>
            </div>
          )}

          <PathInput
            value={config.outputPath || ''}
            onChange={(val) => setConfig(prev => ({ ...prev, outputPath: val }))}
            label={t.outputPathLabel}
            placeholder={t.outputPathPlaceholder}
            icon={Archive}
            mode="directory"
          />
        </div>
      )}

      {/* 4. SAFEGUARDS & BACKUP TAB */}
      {activeTab === 'safeguards' && (
        <div className="dashboard-card animate-fade-in" style={{ marginBottom: '20px' }}>
          <div className="card-header" style={{ marginBottom: '14px' }}>
            <h3 style={{ fontFamily: 'var(--font-orbitron)', fontSize: '1.05rem', color: 'var(--color-green)' }}>{t.sectionSafety}</h3>
          </div>

          {/* Safety Backup Toggle */}
          <div className={`armor-card ${config.backupEnabled ? 'active' : ''}`} style={{ marginBottom: '14px' }}>
            <div className="armor-row" onClick={() => setConfig(prev => ({ ...prev, backupEnabled: !prev.backupEnabled }))}>
              <div className="armor-info">
                <Archive className="armor-icon" size={20} style={{ color: 'var(--color-green)' }} />
                <div>
                  <div className="armor-label-title">{t.backupTitle}</div>
                  <div className="armor-label-desc">{t.backupDesc}</div>
                </div>
              </div>
              <div className="switch-control">
                <div className="switch-knob" />
              </div>
            </div>
            {config.backupEnabled && (
              <div className="armor-subfields">
                <PathInput
                  value={config.backupPath || ''}
                  onChange={(val) => setConfig(prev => ({ ...prev, backupPath: val }))}
                  label={t.backupPathLabel}
                  placeholder={t.backupPathPlaceholder}
                  icon={Folder}
                  mode="directory"
                />
              </div>
            )}
          </div>

          {/* Secure Shredder Toggle */}
          <div className={`armor-card ${config.shredOriginalEnabled ? 'active danger-active' : ''}`} style={{ marginBottom: '14px' }}>
            <div className="armor-row" onClick={() => setConfig(prev => ({ ...prev, shredOriginalEnabled: !prev.shredOriginalEnabled }))}>
              <div className="armor-info">
                <ShieldAlert className="armor-icon" size={20} style={{ color: 'var(--color-red)' }} />
                <div>
                  <div className="armor-label-title" style={{ color: config.shredOriginalEnabled ? 'var(--color-red)' : 'inherit' }}>
                    {t.shredTitle}
                  </div>
                  <div className="armor-label-desc">{t.shredDesc}</div>
                </div>
              </div>
              <div className="switch-control switch-danger">
                <div className="switch-knob" />
              </div>
            </div>
            {config.shredOriginalEnabled && (
              <div className="armor-subfields">
                <div style={{ padding: '10px 14px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: '6px', color: 'var(--color-red)', fontSize: '0.8rem', marginBottom: '12px', lineHeight: 1.4 }}>
                  {t.shredWarning}
                </div>
                <div className="form-group" style={{ marginBottom: 0 }}>
                  <label className="form-label">{t.shredPassesLabel}</label>
                  <select 
                    className="form-input" 
                    style={{ paddingLeft: '14px' }} 
                    value={config.shredPasses || '3'}
                    onChange={(e) => setConfig(prev => ({ ...prev, shredPasses: e.target.value }))}
                  >
                    <option value="1">{t.shredPass1}</option>
                    <option value="3">{t.shredPass3}</option>
                    <option value="7">{t.shredPass7}</option>
                  </select>
                </div>
              </div>
            )}
          </div>

          {/* Metadata Scrubber & Size Obfuscation */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
            <div className={`armor-card ${config.metadataScrubEnabled ? 'active' : ''}`}>
              <div className="armor-row" onClick={() => setConfig(prev => ({ ...prev, metadataScrubEnabled: !prev.metadataScrubEnabled }))}>
                <div className="armor-info">
                  <Trash2 className="armor-icon" size={18} />
                  <div>
                    <div className="armor-label-title" style={{ fontSize: '0.85rem' }}>{t.metaScrubTitle}</div>
                    <div className="armor-label-desc" style={{ fontSize: '0.72rem' }}>{t.metaScrubDesc}</div>
                  </div>
                </div>
                <div className="switch-control">
                  <div className="switch-knob" />
                </div>
              </div>
            </div>

            <div className={`armor-card ${config.sizeObfuscationEnabled ? 'active' : ''}`}>
              <div className="armor-row" onClick={() => setConfig(prev => ({ ...prev, sizeObfuscationEnabled: !prev.sizeObfuscationEnabled }))}>
                <div className="armor-info">
                  <Shuffle className="armor-icon" size={18} />
                  <div>
                    <div className="armor-label-title" style={{ fontSize: '0.85rem' }}>{t.sizeObfTitle}</div>
                    <div className="armor-label-desc" style={{ fontSize: '0.72rem' }}>{t.sizeObfDesc}</div>
                  </div>
                </div>
                <div className="switch-control">
                  <div className="switch-knob" />
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 5. KEYS & RECOVERY TAB */}
      {activeTab === 'keys' && (
        <div className="dashboard-card animate-fade-in" style={{ marginBottom: '24px' }}>
          <div className="card-header" style={{ marginBottom: '14px' }}>
            <h3 style={{ fontFamily: 'var(--font-orbitron)', fontSize: '1.05rem', color: 'var(--color-primary)' }}>{t.sectionKey}</h3>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{t.keyDesc}</p>
          </div>

          <div className="form-group">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <label className="form-label" style={{ margin: 0 }}>{t.passLabel}</label>
              <button
                type="button"
                className="btn-secondary"
                onClick={generateStrongPassword}
                style={{ fontSize: '0.72rem', padding: '3px 8px', display: 'flex', alignItems: 'center', gap: '4px' }}
              >
                <Sparkles size={12} /> {t.generatePassBtn}
              </button>
            </div>
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
            {password && password.length < 10 && (
              <div style={{ color: 'var(--color-red)', fontSize: '0.72rem', marginTop: '6px', fontFamily: 'var(--font-mono)' }}>
                ⚠️ {lang === 'es' ? 'La contraseña maestra debe tener al menos 10 caracteres.' : 'Master password must have at least 10 characters.'}
              </div>
            )}
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

          {/* Hardware Lock Toggle */}
          <div className={`armor-card ${config.hardwareLockEnabled ? 'active' : ''}`}>
            <div className="armor-row" onClick={() => setConfig(prev => ({ ...prev, hardwareLockEnabled: !prev.hardwareLockEnabled }))}>
              <div className="armor-info">
                <Cpu className="armor-icon" size={20} />
                <div>
                  <div className="armor-label-title">{t.hwLockTitle}</div>
                  <div className="armor-label-desc">{t.hwLockDesc}</div>
                </div>
              </div>
              <div className="switch-control">
                <div className="switch-knob" />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SAVE BUTTON */}
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '14px', alignItems: 'center' }}>
        <button
          type="button"
          className="btn-primary"
          onClick={handleSaveConfig}
          disabled={isSaving}
          style={{ minWidth: '220px', padding: '14px 28px', fontSize: '0.95rem' }}
        >
          <Save size={18} /> {isSaving ? t.saving : t.saveBtn}
        </button>
      </div>
    </div>
  );
}
