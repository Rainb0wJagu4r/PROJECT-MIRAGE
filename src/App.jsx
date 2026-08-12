import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Lock, 
  Unlock, 
  ArrowLeft, 
  CheckCircle, 
  Layers, 
  Cpu, 
  Key,
  Eye, 
  EyeOff, 
  Info,
  Sun,
  Moon,
  Globe,
  Copy,
  Check
} from 'lucide-react';
import Dropzone from './components/Dropzone';
import AdvancedOptions from './components/AdvancedOptions';
import PathInput from './components/PathInput';
import ProcessingOverlay from './components/ProcessingOverlay';
import tokenData from './token.json';

// Translations Dictionary
const translations = {
  es: {
    brandSubtitle: "Cifrado Simétrico AES-256-GCM con Extensión .wraith y Blindaje Militar",
    encryptTitle: "Cifrar y Blindar",
    encryptDesc: "Aplica cifrado AES-256 blindado a un archivo con metadatos depurados, ofuscación, bloqueo de hardware y llaves señuelo.",
    decryptTitle: "Descifrar y Restaurar",
    decryptDesc: "Restaura un archivo cifrado (.wraith) o recombina fragmentos de datos divididos verificando firmas criptográficas.",
    // Encrypt console
    encryptConsole: "CONSOLA DE CIFRADO",
    fileToEncrypt: "Archivo a Cifrar (Arrastra o ingresa ruta)",
    orLocalPath: "O ruta del archivo local en disco",
    passwordLabel: "Contraseña Clave (AES-256 Key Derivation)",
    passwordPlaceholder: "Escribe la contraseña de cifrado...",
    dfPasswordLabel: "Contraseña Adicional (Doble Factor)",
    dfPasswordPlaceholder: "Segunda contraseña adicional...",
    optional: "Opcional",
    hintLabel: "Pista de Contraseña (Pública)",
    hintPlaceholder: "Ej: El nombre de mi primer gato...",
    outputPathLabel: "Ruta de Salida del Archivo Cifrado (Opcional)",
    outputPathPlaceholder: "Dejar vacío para guardar en el mismo directorio",
    encryptBtn: "Cifrar y Blindar Archivo",
    // Decrypt console
    decryptConsole: "CONSOLA DE DESCIFRADO",
    recombineLabel: "Recombinar Fragmentos (2-of-3 Split)",
    recombineDesc: "Marca esto si el archivo fue dividido en 3 partes y necesitas recombinarlas.",
    encryptedFilePath: "Ruta del Archivo Cifrado (.wraith)",
    partPathsLabel: "Rutas de los Fragmentos (Ingresa al menos 2 partes)",
    partPlaceholder: "Fragmento",
    addPartBtn: "+ Agregar Ruta de Fragmento",
    removeBtn: "Remover",
    decPasswordLabel: "Contraseña Clave",
    decPasswordPlaceholder: "Ingresa la contraseña principal...",
    restorePathLabel: "Directorio o Ruta de Restauración (Opcional)",
    restorePathPlaceholder: "Ej: /Users/brx/Downloads",
    decryptBtn: "Descifrar y Restaurar Archivo",
    // Success screens
    successEncrypt: "CIFRADO COMPLETADO",
    successDecrypt: "DESCIFRADO COMPLETADO",
    successEncryptDesc: "El archivo ha sido cifrado con AES-256-GCM y blindado exitosamente.",
    successDecryptDesc: "La firma de integridad ha sido verificada y el archivo original fue restaurado.",
    outputFiles: "Archivos de Salida:",
    inputHash: "SHA3 Entrada:",
    outputHash: "SHA3 Salida:",
    passwordHint: "Pista de contraseña:",
    restorePath: "Ruta de Restauración:",
    filename: "Nombre del Archivo:",
    fileSize: "Tamaño del Archivo:",
    integrityCheck: "Verificación de Integridad:",
    passed: "✓ PASADA (GCM Tag válido)",
    hwPepper: "Pepper de Hardware:",
    linkedHost: "✓ Vinculado a este equipo",
    anotherOp: "Realizar otra operación",
    backMenu: "Volver al Menú",
    // Autocomplete
    dragAndDrop: "Arrastra y suelta tu archivo aquí",
    clickExplore: "o haz clic para explorar tus archivos locales",
    pendingHash: "Pendiente...",
    hashInputLabel: "HASH ENTRADA (SHA3-256)",
    hashOutputLabel: "HASH SALIDA .WRAITH (SHA3-256)",
    hashDecryptInputLabel: "HASH ENTRADA .WRAITH (SHA3-256)",
    hashDecryptOutputLabel: "HASH SALIDA (SHA3-256)",
    // Stats card
    decryptSpecs: "ESPECIFICACIONES DE DESCIFRADO",
    algoCore: "Algoritmo Core",
    kdf: "Key Derivation",
    integrityVerify: "Verificación de Integridad:",
    tagVerify: "Tag de Autenticación de 128 bits",
    hwLockTitle: "Bloqueo de Hardware",
    hwLockDesc: "Si el remitente activó el Pepper de Hardware, el archivo solo podrá descifrarse en la computadora exacta donde se cifró.",
    // Extra labels
    back: "Volver",
    statusPreparing: "Preparando archivo subido...",
    statusLoadingLocal: "Cargando archivo local desde ruta...",
    statusLoadingParts: "Cargando fragmentos...",
    statusProcessing: "Procesando flujo de datos criptográficos...",
    statusDecrypting: "DESCIFRANDO Y VALIDANDO INTEGRIDAD...",
    statusEncrypting: "EJECUTANDO BLINDAJE CRIPTOGRÁFICO...",
    errorTitle: "FALLO EN LA OPERACIÓN",
    errorNoFile: "Debes arrastrar un archivo o ingresar una ruta de archivo local.",
    errorNoPassword: "La contraseña es requerida.",
    errorPartsCount: "Debes ingresar al menos 2 rutas de fragmentos para recombinar.",
    errorNoDecFile: "Debes ingresar la ruta del archivo cifrado (.wraith).",
    btnThemeLight: "Modo Claro",
    btnThemeDark: "Modo Oscuro",
    btnLang: "English"
  },
  en: {
    brandSubtitle: "Symmetric AES-256-GCM Cryptography with .wraith extension and Military Armor",
    encryptTitle: "Encrypt & Arm",
    encryptDesc: "Apply armored AES-256 encryption to a file with scrubbed metadata, obfuscation, hardware lock, and decoy keys.",
    decryptTitle: "Decrypt & Restore",
    decryptDesc: "Restore an encrypted file (.wraith) or recombine split data fragments verifying cryptographic signatures.",
    // Encrypt console
    encryptConsole: "ENCRYPTION CONSOLE",
    fileToEncrypt: "File to Encrypt (Drag-and-drop or type path)",
    orLocalPath: "Or local path of file on disk",
    passwordLabel: "Master Password (AES-256 Key Derivation)",
    passwordPlaceholder: "Type your encryption password...",
    dfPasswordLabel: "Additional Password (Two Factor)",
    dfPasswordPlaceholder: "Second additional password...",
    optional: "Optional",
    hintLabel: "Password Hint (Public)",
    hintPlaceholder: "E.g., My first pet's name...",
    outputPathLabel: "Encrypted Output Path (Optional)",
    outputPathPlaceholder: "Leave blank to save in the same directory",
    encryptBtn: "Encrypt & Arm File",
    // Decrypt console
    decryptConsole: "DECRYPTION CONSOLE",
    recombineLabel: "Recombine Fragments (2-of-3 Split)",
    recombineDesc: "Check this if the file was split into 3 parts and you need to recombine them.",
    encryptedFilePath: "Encrypted File Path (.wraith)",
    partPathsLabel: "Fragment Paths (Enter at least 2 parts)",
    partPlaceholder: "Fragment",
    addPartBtn: "+ Add Fragment Path",
    removeBtn: "Remove",
    decPasswordLabel: "Master Password",
    decPasswordPlaceholder: "Enter primary password...",
    restorePathLabel: "Restore Directory or Path (Optional)",
    restorePathPlaceholder: "E.g., /Users/brx/Downloads",
    decryptBtn: "Decrypt & Restore File",
    // Success screens
    successEncrypt: "ENCRYPTION COMPLETED",
    successDecrypt: "DECRYPTION COMPLETED",
    successEncryptDesc: "The file was successfully encrypted with AES-256-GCM and armored.",
    successDecryptDesc: "Integrity signature has been verified and the original file has been restored.",
    outputFiles: "Output Files:",
    inputHash: "SHA3 Input:",
    outputHash: "SHA3 Output:",
    passwordHint: "Password hint:",
    restorePath: "Restore Path:",
    filename: "File Name:",
    fileSize: "File Size:",
    integrityCheck: "Integrity Check:",
    passed: "✓ PASSED (GCM Tag is valid)",
    hwPepper: "Hardware Pepper:",
    linkedHost: "✓ Bound to this host",
    anotherOp: "Perform another operation",
    backMenu: "Back to Menu",
    // Autocomplete
    dragAndDrop: "Drag and drop your file here",
    clickExplore: "or click to browse local files",
    pendingHash: "Pending...",
    hashInputLabel: "INPUT HASH (SHA3-256)",
    hashOutputLabel: "OUTPUT HASH .WRAITH (SHA3-256)",
    hashDecryptInputLabel: "INPUT HASH .WRAITH (SHA3-256)",
    hashDecryptOutputLabel: "OUTPUT HASH (SHA3-256)",
    // Stats card
    decryptSpecs: "DECRYPTION SPECIFICATIONS",
    algoCore: "Core Algorithm",
    kdf: "Key Derivation",
    integrityVerify: "Integrity Verification:",
    tagVerify: "128-bit Authentication Tag",
    hwLockTitle: "Hardware Lock",
    hwLockDesc: "If the sender enabled the Hardware Pepper, the file can only be decrypted on the exact computer where it was encrypted.",
    // Extra labels
    back: "Back",
    statusPreparing: "Preparing uploaded file...",
    statusLoadingLocal: "Loading local file from path...",
    statusLoadingParts: "Loading fragments...",
    statusProcessing: "Processing cryptographic data stream...",
    statusDecrypting: "DECRYPTING AND VERIFYING INTEGRITY...",
    statusEncrypting: "EXECUTING CRYPTOGRAPHIC ARMORING...",
    errorTitle: "OPERATION FAILED",
    errorNoFile: "You must drag a file or enter a local file path.",
    errorNoPassword: "Password is required.",
    errorPartsCount: "You must enter at least 2 fragment paths to recombine.",
    errorNoDecFile: "You must enter the encrypted file path (.wraith).",
    btnThemeLight: "Light Mode",
    btnThemeDark: "Dark Mode",
    btnLang: "Español"
  }
};

export default function App() {
  // Theme & Language States
  const [isDarkMode, setIsDarkMode] = useState(true);
  const [lang, setLang] = useState('es');

  // Clipboard Copy State & Function
  const [copiedField, setCopiedField] = useState(null);
  const copyToClipboard = (text, fieldId) => {
    if (!text || text.startsWith('[') || text === '-') return;
    navigator.clipboard.writeText(text);
    setCopiedField(fieldId);
    setTimeout(() => setCopiedField(null), 1500);
  };

  // Translations reference
  const t = translations[lang] || translations.es;

  // Screen States: 'dashboard', 'encrypt', 'decrypt', 'success'
  const [screen, setScreen] = useState('dashboard');
  
  // System Info
  const [systemInfo, setSystemInfo] = useState(null);

  // Load system info on startup
  useEffect(() => {
    fetch('/api/system-info', {
      headers: { 'X-API-Token': tokenData.token }
    })
      .then(res => res.json())
      .then(data => setSystemInfo(data))
      .catch(err => console.error('Failed to load system info:', err));
  }, []);

  // Handle body theme class toggle
  useEffect(() => {
    if (isDarkMode) {
      document.body.classList.remove('light-theme');
    } else {
      document.body.classList.add('light-theme');
    }
  }, [isDarkMode]);

  // Form State: Encrypt
  const [encFile, setEncFile] = useState(null);
  const [encLocalPath, setEncLocalPath] = useState('');
  const [encPassword, setEncPassword] = useState('');
  const [showEncPassword, setShowEncPassword] = useState(false);
  const [encDoubleFactorPassword, setEncDoubleFactorPassword] = useState('');
  const [showEncDfPassword, setShowEncDfPassword] = useState(false);
  const [encPasswordHint, setEncPasswordHint] = useState('');
  const [encOutputPath, setEncOutputPath] = useState('');
  
  const [encSettings, setEncSettings] = useState({
    metadataScrubEnabled: true,
    sizeObfuscationEnabled: true,
    hardwareLockEnabled: false,
    ttlEnabled: false,
    ttlValue: '1', // 1 hour
    duressEnabled: false,
    duressPassword: '',
    duressDecoyPath: '',
    splitFragmentEnabled: false,
    shredOriginalEnabled: false,
    shredPasses: '3'
  });

  // Form State: Decrypt
  const [decFilePath, setDecFilePath] = useState('');
  const [decPassword, setDecPassword] = useState('');
  const [showDecPassword, setShowDecPassword] = useState(false);
  const [decDoubleFactorPassword, setDecDoubleFactorPassword] = useState('');
  const [showDecDfPassword, setShowDecDfPassword] = useState(false);
  const [decRestorePath, setDecRestorePath] = useState('');
  
  // Split Decrypt States
  const [decIsSplit, setDecIsSplit] = useState(false);
  const [decPartPaths, setDecPartPaths] = useState(['', '']); // User inputs 2 parts

  // Hash Verifier States
  const [encInputHash, setEncInputHash] = useState('');
  const [encOutputHash, setEncOutputHash] = useState('');
  const [decInputHash, setDecInputHash] = useState('');
  const [decOutputHash, setDecOutputHash] = useState('');

  // Fetch hash of encrypt file on change
  useEffect(() => {
    if (encFile) {
      setEncInputHash(lang === 'es' ? '[Cálculo al cifrar...]' : '[Calculation pending encryption...]');
      return;
    }
    if (!encLocalPath) {
      setEncInputHash('');
      return;
    }
    const timer = setTimeout(async () => {
      try {
        const response = await fetch(`/api/file-info?path=${encodeURIComponent(encLocalPath)}`, {
          headers: { 'X-API-Token': tokenData.token }
        });
        const data = await response.json();
        if (data && data.exists && data.hash) {
          setEncInputHash(data.hash);
        } else {
          setEncInputHash('');
        }
      } catch (e) {
        setEncInputHash('');
      }
    }, 400);
    return () => clearTimeout(timer);
  }, [encLocalPath, encFile, lang]);

  // Fetch hash of decrypt file on change
  useEffect(() => {
    if (!decFilePath) {
      setDecInputHash('');
      return;
    }
    const timer = setTimeout(async () => {
      try {
        const response = await fetch(`/api/file-info?path=${encodeURIComponent(decFilePath)}`, {
          headers: { 'X-API-Token': tokenData.token }
        });
        const data = await response.json();
        if (data && data.exists && data.hash) {
          setDecInputHash(data.hash);
        } else {
          setDecInputHash('');
        }
      } catch (e) {
        setDecInputHash('');
      }
    }, 400);
    return () => clearTimeout(timer);
  }, [decFilePath]);

  // Processing Modal States
  const [isProcessing, setIsProcessing] = useState(false);
  const [processingTitle, setProcessingTitle] = useState('');
  const [processingSteps, setProcessingSteps] = useState([]);
  const [processingError, setProcessingError] = useState(null);

  // Success Screen Data
  const [successData, setSuccessData] = useState(null);

  const handleEncSettingChange = (key, val) => {
    setEncSettings(prev => ({ ...prev, [key]: val }));
  };

  // Execute Encrypt Action
  const handleEncryptSubmit = async (e) => {
    e.preventDefault();
    setProcessingError(null);
    setProcessingSteps([]);
    setProcessingTitle(t.statusEncrypting);
    setIsProcessing(true);

    try {
      let response;
      
      // Determine if uploading raw file or path reference
      if (encFile) {
        setProcessingSteps([{ msg: `${t.statusPreparing} ${encFile.name}...`, success: true }]);
        
        const settingsPayload = {
          password: encPassword,
          doubleFactorPassword: encDoubleFactorPassword,
          hardwareLockEnabled: encSettings.hardwareLockEnabled,
          metadataScrubEnabled: encSettings.metadataScrubEnabled,
          sizeObfuscationEnabled: encSettings.sizeObfuscationEnabled,
          ttlEnabled: encSettings.ttlEnabled,
          ttlValue: encSettings.ttlValue,
          duressEnabled: encSettings.duressEnabled,
          duressPassword: encSettings.duressPassword,
          duressDecoyPath: encSettings.duressDecoyPath,
          splitFragmentEnabled: encSettings.splitFragmentEnabled,
          shredOriginalEnabled: false,
          outputPath: encOutputPath
        };

        const headers = {
          'Content-Type': 'application/octet-stream',
          'X-File-Name': encodeURIComponent(encFile.name),
          'X-Settings': JSON.stringify(settingsPayload),
          'X-API-Token': tokenData.token
        };

        response = await fetch('/api/encrypt', {
          method: 'POST',
          headers,
          body: encFile
        });
      } else {
        if (!encLocalPath) {
          throw new Error(t.errorNoFile);
        }

        setProcessingSteps([{ msg: `${t.statusLoadingLocal} ${encLocalPath}...`, success: true }]);
        
        response = await fetch('/api/encrypt', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'X-API-Token': tokenData.token
          },
          body: JSON.stringify({
            filePath: encLocalPath,
            settings: {
              password: encPassword,
              doubleFactorPassword: encDoubleFactorPassword,
              hardwareLockEnabled: encSettings.hardwareLockEnabled,
              metadataScrubEnabled: encSettings.metadataScrubEnabled,
              sizeObfuscationEnabled: encSettings.sizeObfuscationEnabled,
              ttlEnabled: encSettings.ttlEnabled,
              ttlValue: encSettings.ttlValue,
              duressEnabled: encSettings.duressEnabled,
              duressPassword: encSettings.duressPassword,
              duressDecoyPath: encSettings.duressDecoyPath,
              splitFragmentEnabled: encSettings.splitFragmentEnabled,
              shredOriginalEnabled: encSettings.shredOriginalEnabled,
              shredPasses: encSettings.shredPasses,
              outputPath: encOutputPath
            }
          })
        });
      }

      const data = await response.json();
      
      if (data.steps) {
        setProcessingSteps(data.steps);
      }

      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Crypto Fail');
      }

      // Success
      setTimeout(() => {
        setEncInputHash(data.inputHash);
        setEncOutputHash(data.outputHash);
        setSuccessData({
          type: 'encrypt',
          outputPath: data.outputPath,
          inputHash: data.inputHash,
          outputHash: data.outputHash,
          split: encSettings.splitFragmentEnabled,
          hint: encPasswordHint
        });
        setIsProcessing(false);
        setScreen('success');
      }, 800);

    } catch (err) {
      setProcessingError(err.message);
      setProcessingSteps(prev => [...prev, { msg: `Fail: ${err.message}`, success: false }]);
    }
  };

  // Execute Decrypt Action
  const handleDecryptSubmit = async (e) => {
    e.preventDefault();
    setProcessingError(null);
    setProcessingSteps([]);
    setProcessingTitle(t.statusDecrypting);
    setIsProcessing(true);

    try {
      let payload = {
        password: decPassword,
        doubleFactorPassword: decDoubleFactorPassword,
        restorePath: decRestorePath
      };

      if (decIsSplit) {
        const filteredParts = decPartPaths.filter(p => p.trim() !== '');
        if (filteredParts.length < 2) {
          throw new Error(t.errorPartsCount);
        }
        payload.partPaths = filteredParts;
        setProcessingSteps([{ msg: `${t.statusLoadingParts} ${filteredParts.join(', ')}...`, success: true }]);
      } else {
        if (!decFilePath) {
          throw new Error(t.errorNoDecFile);
        }
        payload.filePath = decFilePath;
        setProcessingSteps([{ msg: `Loading encrypted file from: ${decFilePath}...`, success: true }]);
      }

      const response = await fetch('/api/decrypt', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'X-API-Token': tokenData.token
        },
        body: JSON.stringify(payload)
      });

      const data = await response.json();
      
      if (data.steps) {
        setProcessingSteps(data.steps);
      }

      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Authentication failure.');
      }

      // Success
      setTimeout(() => {
        setDecOutputHash(data.outputHash);
        setSuccessData({
          type: 'decrypt',
          outputPath: data.restorePath,
          filename: data.filename,
          fileSize: data.fileSize,
          outputHash: data.outputHash,
          hwLocked: data.hardwareLockVerified
        });
        setIsProcessing(false);
        setScreen('success');
      }, 800);

    } catch (err) {
      setProcessingError(err.message);
      setProcessingSteps(prev => [...prev, { msg: `Fail: ${err.message}`, success: false }]);
    }
  };

  const addPartPathField = () => {
    setDecPartPaths(prev => [...prev, '']);
  };

  const removePartPathField = (idx) => {
    if (decPartPaths.length <= 2) return;
    setDecPartPaths(prev => prev.filter((_, i) => i !== idx));
  };

  const updatePartPath = (idx, val) => {
    setDecPartPaths(prev => {
      const copy = [...prev];
      copy[idx] = val;
      return copy;
    });
  };

  const resetForms = () => {
    setEncFile(null);
    setEncLocalPath('');
    setEncPassword('');
    setEncDoubleFactorPassword('');
    setEncPasswordHint('');
    setEncOutputPath('');
    setEncInputHash('');
    setEncOutputHash('');
    setEncSettings({
      metadataScrubEnabled: true,
      sizeObfuscationEnabled: true,
      hardwareLockEnabled: false,
      ttlEnabled: false,
      ttlValue: '1',
      duressEnabled: false,
      duressPassword: '',
      duressDecoyPath: '',
      splitFragmentEnabled: false,
      shredOriginalEnabled: false,
      shredPasses: '3'
    });
    setDecFilePath('');
    setDecPassword('');
    setDecDoubleFactorPassword('');
    setDecRestorePath('');
    setDecInputHash('');
    setDecOutputHash('');
    setDecIsSplit(false);
    setDecPartPaths(['', '']);
    setSuccessData(null);
    setScreen('dashboard');
  };

  return (
    <div className="app-container">
      {/* Settings / Controls Bar */}
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginBottom: '-10px', zIndex: 10 }}>
        <button 
          type="button" 
          className="btn-secondary" 
          onClick={() => setIsDarkMode(!isDarkMode)}
          style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', padding: '6px 12px' }}
        >
          {isDarkMode ? <Sun size={14} /> : <Moon size={14} />}
          {isDarkMode ? t.btnThemeLight : t.btnThemeDark}
        </button>
        <button 
          type="button" 
          className="btn-secondary" 
          onClick={() => setLang(lang === 'es' ? 'en' : 'es')}
          style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', padding: '6px 12px' }}
        >
          <Globe size={14} />
          {t.btnLang}
        </button>
      </div>

      {/* Brand Header */}
      <header className="app-header">
        <h1 className="brand-title">
          <Shield className="brand-logo-icon" size={38} style={{ color: 'var(--color-primary)' }} />
          PROJECT MIRAGE
        </h1>
        <p className="brand-subtitle">
          {t.brandSubtitle}
        </p>
        {systemInfo && (
          <div style={{ marginTop: '10px', fontSize: '0.75rem', color: 'var(--text-dark)', fontFamily: 'var(--font-mono)' }}>
            HOST: {systemInfo.hostname} ({systemInfo.platform}) | HW UUID: {systemInfo.uuid.substring(0, 18)}...
          </div>
        )}
      </header>

      {/* 1. Dashboard View */}
      {screen === 'dashboard' && (
        <main className="dashboard-grid">
          <div className="mode-card encrypt-card" onClick={() => setScreen('encrypt')}>
            <div className="mode-icon-wrapper">
              <Lock size={44} />
            </div>
            <h2 className="mode-title">{t.encryptTitle}</h2>
            <p className="mode-desc">
              {t.encryptDesc}
            </p>
          </div>

          <div className="mode-card decrypt-card" onClick={() => setScreen('decrypt')}>
            <div className="mode-icon-wrapper">
              <Unlock size={44} />
            </div>
            <h2 className="mode-title">{t.decryptTitle}</h2>
            <p className="mode-desc">
              {t.decryptDesc}
            </p>
          </div>
        </main>
      )}

      {/* 2. Encrypt View */}
      {screen === 'encrypt' && (
        <main className="console-wrapper">
          <div className="console-header">
            <h2 className="console-title">
              <Lock size={22} style={{ color: 'var(--color-primary)' }} />
              {t.encryptConsole}
            </h2>
            <button className="back-btn" onClick={() => setScreen('dashboard')}>
              <ArrowLeft size={16} /> {t.back}
            </button>
          </div>

          <form onSubmit={handleEncryptSubmit} className="console-grid">
            {/* Left Column: Core File & Password configuration */}
            <div>
              <div className="form-group">
                <label className="form-label">{t.fileToEncrypt}</label>
                <Dropzone 
                  file={encFile} 
                  setFile={setEncFile} 
                  onFileSelected={(f) => {
                    if (f) setEncLocalPath('');
                  }}
                  lang={lang}
                />
              </div>

              {!encFile && (
                <PathInput
                  value={encLocalPath}
                  onChange={setEncLocalPath}
                  placeholder="Ej: /Users/brx/documents/secreto.pdf"
                  label={t.orLocalPath}
                />
              )}

              <div className="form-group">
                <label className="form-label">{t.passwordLabel}</label>
                <div className="form-input-wrapper">
                  <Key className="form-input-icon" size={18} />
                  <input
                    type={showEncPassword ? "text" : "password"}
                    className="form-input"
                    value={encPassword}
                    onChange={(e) => setEncPassword(e.target.value)}
                    placeholder={t.passwordPlaceholder}
                    required
                  />
                  <button
                    type="button"
                    style={{ position: 'absolute', right: '14px', background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
                    onClick={() => setShowEncPassword(!showEncPassword)}
                  >
                    {showEncPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>

              <div className="form-group">
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                  <label className="form-label" style={{ marginBottom: 0 }}>{t.dfPasswordLabel}</label>
                  <span className="crypto-badge" style={{ fontSize: '0.65rem', padding: '2px 5px' }}>{t.optional}</span>
                </div>
                <div className="form-input-wrapper">
                  <Key className="form-input-icon" size={18} />
                  <input
                    type={showEncDfPassword ? "text" : "password"}
                    className="form-input"
                    value={encDoubleFactorPassword}
                    onChange={(e) => setEncDoubleFactorPassword(e.target.value)}
                    placeholder={t.dfPasswordPlaceholder}
                  />
                  <button
                    type="button"
                    style={{ position: 'absolute', right: '14px', background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
                    onClick={() => setShowEncDfPassword(!showEncDfPassword)}
                  >
                    {showEncDfPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">{t.hintLabel}</label>
                <div className="form-input-wrapper">
                  <Info className="form-input-icon" size={18} />
                  <input
                    type="text"
                    className="form-input"
                    value={encPasswordHint}
                    onChange={(e) => setEncPasswordHint(e.target.value)}
                    placeholder={t.hintPlaceholder}
                  />
                </div>
              </div>

              <PathInput
                value={encOutputPath}
                onChange={setEncOutputPath}
                placeholder={t.outputPathPlaceholder}
                label={t.outputPathLabel}
              />

              {/* Real-time Hash Verifier Displays */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px', marginTop: '20px', marginBottom: '20px' }}>
                <div className="form-group" style={{ marginBottom: 0 }}>
                  <label className="form-label" style={{ fontSize: '0.8rem' }}>{t.hashInputLabel}</label>
                  <div className="form-input-wrapper">
                    <input
                      type="text"
                      className="form-input"
                      style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', paddingLeft: '14px', paddingRight: '40px', background: 'rgba(0,0,0,0.25)', color: 'var(--color-cyan)' }}
                      value={encInputHash || '-'}
                      readOnly
                      placeholder={t.pendingHash}
                    />
                    {encInputHash && encInputHash !== '-' && !encInputHash.startsWith('[') && (
                      <button
                        type="button"
                        style={{ position: 'absolute', right: '14px', background: 'none', border: 'none', color: copiedField === 'encInput' ? 'var(--color-green)' : 'var(--text-muted)', cursor: 'pointer', display: 'flex', alignItems: 'center' }}
                        onClick={() => copyToClipboard(encInputHash, 'encInput')}
                        title="Copiar hash"
                      >
                        {copiedField === 'encInput' ? <Check size={14} /> : <Copy size={14} />}
                      </button>
                    )}
                  </div>
                </div>
                <div className="form-group" style={{ marginBottom: 0 }}>
                  <label className="form-label" style={{ fontSize: '0.8rem' }}>{t.hashOutputLabel}</label>
                  <div className="form-input-wrapper">
                    <input
                      type="text"
                      className="form-input"
                      style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', paddingLeft: '14px', paddingRight: '40px', background: 'rgba(0,0,0,0.25)', color: 'var(--color-primary)' }}
                      value={encOutputHash || '-'}
                      readOnly
                      placeholder={t.pendingHash}
                    />
                    {encOutputHash && encOutputHash !== '-' && !encOutputHash.startsWith('[') && (
                      <button
                        type="button"
                        style={{ position: 'absolute', right: '14px', background: 'none', border: 'none', color: copiedField === 'encOutput' ? 'var(--color-green)' : 'var(--text-muted)', cursor: 'pointer', display: 'flex', alignItems: 'center' }}
                        onClick={() => copyToClipboard(encOutputHash, 'encOutput')}
                        title="Copiar hash"
                      >
                        {copiedField === 'encOutput' ? <Check size={14} /> : <Copy size={14} />}
                      </button>
                    )}
                  </div>
                </div>
              </div>

              <div className="action-btn-wrapper">
                <button 
                  type="submit" 
                  className="action-btn"
                  disabled={!encPassword || (!encFile && !encLocalPath)}
                >
                  <Lock size={20} />
                  {t.encryptBtn}
                </button>
              </div>
            </div>

            {/* Right Column: Advanced Options Accordion */}
            <div>
              <AdvancedOptions 
                settings={encSettings} 
                setSetting={handleEncSettingChange} 
                lang={lang}
              />
            </div>
          </form>
        </main>
      )}

      {/* 3. Decrypt View */}
      {screen === 'decrypt' && (
        <main className="console-wrapper">
          <div className="console-header">
            <h2 className="console-title">
              <Unlock size={22} style={{ color: 'var(--color-cyan)' }} />
              {t.decryptConsole}
            </h2>
            <button className="back-btn" onClick={() => setScreen('dashboard')}>
              <ArrowLeft size={16} /> {t.back}
            </button>
          </div>

          <form onSubmit={handleDecryptSubmit} className="console-grid">
            {/* Left Column: Decrypt inputs */}
            <div>
              {/* Split switch */}
              <div className="form-group">
                <div className={`armor-card ${decIsSplit ? 'active' : ''}`} style={{ borderStyle: 'dashed' }}>
                  <div className="armor-row" onClick={() => setDecIsSplit(!decIsSplit)}>
                    <div className="armor-info">
                      <Layers className="armor-icon" size={20} style={{ color: decIsSplit ? 'var(--color-cyan)' : 'var(--text-muted)' }} />
                      <div>
                        <div className="armor-label-title">{t.recombineLabel}</div>
                        <div className="armor-label-desc">{t.recombineDesc}</div>
                      </div>
                    </div>
                    <div className="switch-control" style={{ backgroundColor: decIsSplit ? 'var(--color-cyan)' : '' }}>
                      <div className="switch-knob" />
                    </div>
                  </div>
                </div>
              </div>

              {!decIsSplit ? (
                <PathInput
                  value={decFilePath}
                  onChange={setDecFilePath}
                  placeholder="Ej: /Users/brx/documents/secreto.wraith"
                  label={t.encryptedFilePath}
                />
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  <label className="form-label" style={{ marginBottom: '2px' }}>{t.partPathsLabel}</label>
                  {decPartPaths.map((partPath, idx) => (
                    <div key={idx} style={{ display: 'flex', gap: '10px', style: { alignItems: 'flex-start' } }}>
                      <div style={{ flex: 1 }}>
                        <PathInput
                          value={partPath}
                          onChange={(val) => updatePartPath(idx, val)}
                          placeholder={`${t.partPlaceholder} ${idx + 1}`}
                        />
                      </div>
                      {decPartPaths.length > 2 && (
                        <button 
                          type="button" 
                          className="btn-secondary" 
                          onClick={() => removePartPathField(idx)}
                          style={{ marginTop: '30px', padding: '12px', borderColor: 'var(--color-red)' }}
                        >
                          {t.removeBtn}
                        </button>
                      )}
                    </div>
                  ))}
                  <button 
                    type="button" 
                    className="btn-secondary" 
                    onClick={addPartPathField}
                    style={{ alignSelf: 'flex-start', fontSize: '0.8rem', padding: '8px 14px', marginBottom: '15px' }}
                  >
                    {t.addPartBtn}
                  </button>
                </div>
              )}

              <div className="form-group">
                <label className="form-label">{t.decPasswordLabel}</label>
                <div className="form-input-wrapper">
                  <Key className="form-input-icon" size={18} />
                  <input
                    type={showDecPassword ? "text" : "password"}
                    className="form-input"
                    value={decPassword}
                    onChange={(e) => setDecPassword(e.target.value)}
                    placeholder={t.decPasswordPlaceholder}
                    required
                  />
                  <button
                    type="button"
                    style={{ position: 'absolute', right: '14px', background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
                    onClick={() => setShowDecPassword(!showDecPassword)}
                  >
                    {showDecPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>

              <div className="form-group">
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                  <label className="form-label" style={{ marginBottom: 0 }}>{t.dfPasswordLabel}</label>
                  <span className="crypto-badge" style={{ fontSize: '0.65rem', padding: '2px 5px', color: 'var(--color-cyan)', borderColor: 'rgba(6, 182, 212, 0.25)' }}>{t.optional}</span>
                </div>
                <div className="form-input-wrapper">
                  <Key className="form-input-icon" size={18} />
                  <input
                    type={showDecDfPassword ? "text" : "password"}
                    className="form-input"
                    value={decDoubleFactorPassword}
                    onChange={(e) => setDecDoubleFactorPassword(e.target.value)}
                    placeholder={t.dfPasswordPlaceholder}
                  />
                  <button
                    type="button"
                    style={{ position: 'absolute', right: '14px', background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
                    onClick={() => setShowDecDfPassword(!showDecDfPassword)}
                  >
                    {showDecDfPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>

              <PathInput
                value={decRestorePath}
                onChange={setDecRestorePath}
                placeholder={t.restorePathPlaceholder}
                label={t.restorePathLabel}
              />

              {/* Decrypt Real-time Hash Verifier */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px', marginTop: '20px', marginBottom: '20px' }}>
                <div className="form-group" style={{ marginBottom: 0 }}>
                  <label className="form-label" style={{ fontSize: '0.8rem' }}>{t.hashDecryptInputLabel}</label>
                  <div className="form-input-wrapper">
                    <input
                      type="text"
                      className="form-input"
                      style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', paddingLeft: '14px', paddingRight: '40px', background: 'rgba(0,0,0,0.25)', color: 'var(--color-primary)' }}
                      value={decInputHash || '-'}
                      readOnly
                      placeholder={t.pendingHash}
                    />
                    {decInputHash && decInputHash !== '-' && !decInputHash.startsWith('[') && (
                      <button
                        type="button"
                        style={{ position: 'absolute', right: '14px', background: 'none', border: 'none', color: copiedField === 'decInput' ? 'var(--color-green)' : 'var(--text-muted)', cursor: 'pointer', display: 'flex', alignItems: 'center' }}
                        onClick={() => copyToClipboard(decInputHash, 'decInput')}
                        title="Copiar hash"
                      >
                        {copiedField === 'decInput' ? <Check size={14} /> : <Copy size={14} />}
                      </button>
                    )}
                  </div>
                </div>
                <div className="form-group" style={{ marginBottom: 0 }}>
                  <label className="form-label" style={{ fontSize: '0.8rem' }}>{t.hashDecryptOutputLabel}</label>
                  <div className="form-input-wrapper">
                    <input
                      type="text"
                      className="form-input"
                      style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', paddingLeft: '14px', paddingRight: '40px', background: 'rgba(0,0,0,0.25)', color: 'var(--color-green)' }}
                      value={decOutputHash || '-'}
                      readOnly
                      placeholder={t.pendingHash}
                    />
                    {decOutputHash && decOutputHash !== '-' && !decOutputHash.startsWith('[') && (
                      <button
                        type="button"
                        style={{ position: 'absolute', right: '14px', background: 'none', border: 'none', color: copiedField === 'decOutput' ? 'var(--color-green)' : 'var(--text-muted)', cursor: 'pointer', display: 'flex', alignItems: 'center' }}
                        onClick={() => copyToClipboard(decOutputHash, 'decOutput')}
                        title="Copiar hash"
                      >
                        {copiedField === 'decOutput' ? <Check size={14} /> : <Copy size={14} />}
                      </button>
                    )}
                  </div>
                </div>
              </div>

              <div className="action-btn-wrapper">
                <button 
                  type="submit" 
                  className="action-btn decrypt-theme"
                  disabled={!decPassword || (!decIsSplit && !decFilePath)}
                >
                  <Unlock size={20} />
                  {t.decryptBtn}
                </button>
              </div>
            </div>

            {/* Right Column: Security specifications */}
            <div>
              <div className="security-stats-card">
                <div>
                  <h3 style={{ fontFamily: 'var(--font-orbitron)', fontSize: '1rem', letterSpacing: '0.5px', marginBottom: '20px', color: 'var(--text-muted)' }}>
                    {t.decryptSpecs}
                  </h3>
                  
                  <div className="stat-item">
                    <div className="stat-header">{t.algoCore}</div>
                    <div className="stat-value" style={{ color: 'var(--color-cyan)' }}>AES-256-GCM (Authenticated)</div>
                  </div>

                  <div className="stat-item">
                    <div className="stat-header">{t.kdf}</div>
                    <div className="stat-value">Scrypt (Memory-Hard PBKDF)</div>
                  </div>

                  <div className="stat-item">
                    <div className="stat-header">{t.integrityVerify}</div>
                    <div className="stat-value">{t.tagVerify}</div>
                  </div>
                </div>

                <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)', borderRadius: '12px', padding: '15px' }}>
                  <div style={{ display: 'flex', gap: '10px', alignItems: 'center', marginBottom: '8px' }}>
                    <Cpu size={18} style={{ color: 'var(--color-cyan)' }} />
                    <span style={{ fontWeight: 600, fontSize: '0.85rem' }}>{t.hwLockTitle}</span>
                  </div>
                  <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', lineHeight: '1.4' }}>
                    {t.hwLockDesc}
                  </p>
                </div>
              </div>
            </div>
          </form>
        </main>
      )}

      {/* 4. Success Summary View */}
      {screen === 'success' && successData && (
        <main className="console-wrapper" style={{ maxWidth: '650px', margin: '30px auto' }}>
          <div className="success-screen">
            <div className="success-badge">
              <CheckCircle size={44} />
            </div>
            
            <h2 className="success-title">
              {successData.type === 'encrypt' ? t.successEncrypt : t.successDecrypt}
            </h2>
            <p className="success-subtitle">
              {successData.type === 'encrypt' ? t.successEncryptDesc : t.successDecryptDesc}
            </p>

            <div className="result-card">
              {successData.type === 'encrypt' ? (
                <>
                  <div className="result-row" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span className="result-key">{t.outputFiles}</span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
                      <span className="result-val highlight" style={{ color: 'var(--color-primary)', margin: 0 }}>
                        {successData.outputPath}
                      </span>
                      <button
                        type="button"
                        style={{ background: 'none', border: 'none', color: copiedField === 'succOutputFiles' ? 'var(--color-green)' : 'var(--text-muted)', cursor: 'pointer', flexShrink: 0, display: 'flex', alignItems: 'center' }}
                        onClick={() => copyToClipboard(successData.outputPath, 'succOutputFiles')}
                        title="Copiar ruta"
                      >
                        {copiedField === 'succOutputFiles' ? <Check size={12} /> : <Copy size={12} />}
                      </button>
                    </div>
                  </div>
                  <div className="result-row" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span className="result-key">{t.inputHash}</span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
                      <span className="result-val" style={{ margin: 0, fontSize: '0.75rem', wordBreak: 'break-all' }}>{successData.inputHash}</span>
                      <button
                        type="button"
                        style={{ background: 'none', border: 'none', color: copiedField === 'succInputHash' ? 'var(--color-green)' : 'var(--text-muted)', cursor: 'pointer', flexShrink: 0, display: 'flex', alignItems: 'center' }}
                        onClick={() => copyToClipboard(successData.inputHash, 'succInputHash')}
                        title="Copiar hash"
                      >
                        {copiedField === 'succInputHash' ? <Check size={12} /> : <Copy size={12} />}
                      </button>
                    </div>
                  </div>
                  <div className="result-row" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span className="result-key">{t.outputHash}</span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
                      <span className="result-val" style={{ margin: 0, fontSize: '0.75rem', wordBreak: 'break-all' }}>{successData.outputHash}</span>
                      <button
                        type="button"
                        style={{ background: 'none', border: 'none', color: copiedField === 'succOutputHash' ? 'var(--color-green)' : 'var(--text-muted)', cursor: 'pointer', flexShrink: 0, display: 'flex', alignItems: 'center' }}
                        onClick={() => copyToClipboard(successData.outputHash, 'succOutputHash')}
                        title="Copiar hash"
                      >
                        {copiedField === 'succOutputHash' ? <Check size={12} /> : <Copy size={12} />}
                      </button>
                    </div>
                  </div>
                  {successData.hint && (
                    <div className="result-row">
                      <span className="result-key">{t.passwordHint}</span>
                      <span className="result-val" style={{ fontStyle: 'italic' }}>"{successData.hint}"</span>
                    </div>
                  )}
                </>
              ) : (
                <>
                  <div className="result-row" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span className="result-key">{t.restorePath}</span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
                      <span className="result-val highlight" style={{ margin: 0 }}>
                        {successData.outputPath}
                      </span>
                      <button
                        type="button"
                        style={{ background: 'none', border: 'none', color: copiedField === 'succRestorePath' ? 'var(--color-green)' : 'var(--text-muted)', cursor: 'pointer', flexShrink: 0, display: 'flex', alignItems: 'center' }}
                        onClick={() => copyToClipboard(successData.outputPath, 'succRestorePath')}
                        title="Copiar ruta"
                      >
                        {copiedField === 'succRestorePath' ? <Check size={12} /> : <Copy size={12} />}
                      </button>
                    </div>
                  </div>
                  <div className="result-row">
                    <span className="result-key">{t.filename}</span>
                    <span className="result-val">{successData.filename}</span>
                  </div>
                  <div className="result-row">
                    <span className="result-key">{t.fileSize}</span>
                    <span className="result-val">{(successData.fileSize / 1024).toFixed(2)} KB</span>
                  </div>
                  <div className="result-row" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span className="result-key">{t.outputHash}</span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
                      <span className="result-val" style={{ margin: 0, fontSize: '0.75rem', wordBreak: 'break-all' }}>{successData.outputHash}</span>
                      <button
                        type="button"
                        style={{ background: 'none', border: 'none', color: copiedField === 'succDecHash' ? 'var(--color-green)' : 'var(--text-muted)', cursor: 'pointer', flexShrink: 0, display: 'flex', alignItems: 'center' }}
                        onClick={() => copyToClipboard(successData.outputHash, 'succDecHash')}
                        title="Copiar hash"
                      >
                        {copiedField === 'succDecHash' ? <Check size={12} /> : <Copy size={12} />}
                      </button>
                    </div>
                  </div>
                  <div className="result-row">
                    <span className="result-key">{t.integrityCheck}</span>
                    <span className="result-val" style={{ color: 'var(--color-green)' }}>{t.passed}</span>
                  </div>
                  {successData.hwLocked && (
                    <div className="result-row">
                      <span className="result-key">{t.hwPepper}</span>
                      <span className="result-val" style={{ color: 'var(--color-cyan)' }}>{t.linkedHost}</span>
                    </div>
                  )}
                </>
              )}
            </div>

            <div className="success-actions">
              <button className="btn-secondary" onClick={resetForms}>
                {t.anotherOp}
              </button>
              <button 
                className="action-btn"
                style={{ 
                  background: successData.type === 'encrypt' 
                    ? 'linear-gradient(135deg, var(--color-primary) 0%, #7c3aed 100%)' 
                    : 'linear-gradient(135deg, var(--color-cyan) 0%, #0891b2 100%)',
                  boxShadow: successData.type === 'encrypt' 
                    ? '0 8px 20px var(--color-primary-glow)' 
                    : '0 8px 20px var(--color-cyan-glow)'
                }}
                onClick={resetForms}
              >
                {t.backMenu}
              </button>
            </div>
          </div>
        </main>
      )}

      {/* Live Processing Scanning Overlay */}
      <ProcessingOverlay 
        isOpen={isProcessing}
        title={processingTitle}
        steps={processingSteps}
        error={processingError}
        onClose={() => setIsProcessing(false)}
      />

      {/* Footer */}
      <footer style={{ marginTop: 'auto', paddingTop: '40px', paddingBottom: '20px', textAlign: 'center', fontSize: '0.85rem', color: 'var(--text-dark)', fontFamily: 'var(--font-outfit)', letterSpacing: '0.5px' }}>
        Made with ♥️ by MDVsecurity from 🇲🇽
      </footer>
    </div>
  );
}
