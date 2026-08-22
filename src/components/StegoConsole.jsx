import React, { useState } from 'react';
import { 
  Lock, 
  Unlock, 
  Image, 
  Key, 
  Eye, 
  EyeOff, 
  CheckCircle,
  Copy,
  Check
} from 'lucide-react';
import Dropzone from './Dropzone';
import PathInput from './PathInput';
export default function StegoConsole({ token, t, lang, onBack, onStartProcessing, onFinishProcessing, onProcessingStep }) {
  const [activeTab, setActiveTab] = useState('hide'); // 'hide' or 'reveal'
  
  // Hide form state
  const [hideFile, setHideFile] = useState(null);
  const [hideLocalPath, setHideLocalPath] = useState('');
  const [carrierFile, setCarrierFile] = useState(null);
  const [carrierLocalPath, setCarrierLocalPath] = useState('');
  const [hidePassword, setHidePassword] = useState('');
  const [hideDfPassword, setHideDfPassword] = useState('');
  const [showHidePassword, setShowHidePassword] = useState(false);
  const [hideAlgorithm, setHideAlgorithm] = useState('aes-256-gcm');
  const [hideOutputPath, setHideOutputPath] = useState('');

  // Reveal form state
  const [revealFile, setRevealFile] = useState(null);
  const [revealLocalPath, setRevealLocalPath] = useState('');
  const [revealPassword, setRevealPassword] = useState('');
  const [showRevealPassword, setShowRevealPassword] = useState(false);
  const [revealOutputPath, setRevealOutputPath] = useState('');
  
  // Result state
  const [result, setResult] = useState(null);
  const [copiedField, setCopiedField] = useState('');

  // Clipboard helper
  const copyToClipboard = (text, field) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(''), 2000);
  };

  const handleHideSubmit = async (e) => {
    e.preventDefault();
    onStartProcessing(lang === 'es' ? 'EJECUTANDO OCULTACIÓN ESTEGANOGRÁFICA...' : 'EXECUTING STEGANOGRAPHIC CONCEALMENT...');
    
    try {
      let response;
      const settingsPayload = {
        password: hidePassword,
        doubleFactorPassword: hideDfPassword,
        hardwareLockEnabled: false,
        metadataScrubEnabled: true,
        sizeObfuscationEnabled: false,
        ttlEnabled: false,
        ttlValue: '1',
        duressEnabled: false,
        duressPassword: '',
        duressDecoyPath: '',
        splitFragmentEnabled: false,
        shredOriginalEnabled: false,
        outputPath: hideOutputPath,
        algorithm: hideAlgorithm,
        steganographyEnabled: true,
        carrierPath: carrierLocalPath
      };

      if (hideFile) {
        onProcessingStep({ msg: lang === 'es' ? `Cargando archivo ${hideFile.name}...` : `Loading file ${hideFile.name}...`, success: true });
        
        const headers = {
          'Content-Type': 'application/octet-stream',
          'X-File-Name': encodeURIComponent(hideFile.name),
          'X-Settings': JSON.stringify(settingsPayload),
          'X-API-Token': token
        };

        response = await fetch('/api/encrypt', {
          method: 'POST',
          headers,
          body: hideFile
        });
      } else {
        if (!hideLocalPath) {
          throw new Error(lang === 'es' ? 'Debes seleccionar un archivo a cifrar.' : 'You must select a file to encrypt.');
        }
        onProcessingStep({ msg: lang === 'es' ? `Cargando archivo local ${hideLocalPath}...` : `Loading local file ${hideLocalPath}...`, success: true });
        
        response = await fetch('/api/encrypt', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-API-Token': token
          },
          body: JSON.stringify({
            filePath: hideLocalPath,
            settings: settingsPayload
          })
        });
      }

      const data = await response.json();
      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Steganography concealment failed.');
      }

      onProcessingStep({ msg: lang === 'es' ? 'Escritura esteganográfica completada exitosamente.' : 'Steganographic write completed successfully.', success: true });
      
      setTimeout(() => {
        setResult({
          type: 'hide',
          outputPath: data.outputPath,
          inputHash: data.inputHash,
          outputHash: data.outputHash,
          algorithm: hideAlgorithm
        });
        onFinishProcessing();
      }, 800);

    } catch (err) {
      onFinishProcessing(err.message);
    }
  };

  const handleRevealSubmit = async (e) => {
    e.preventDefault();
    onStartProcessing(lang === 'es' ? 'EXTRAYENDO Y DESCIFRANDO PAYLOAD...' : 'EXTRACTING AND DECRYPTING PAYLOAD...');

    try {
      let response;
      const payload = {
        password: revealPassword,
        doubleFactorPassword: '',
        restorePath: revealOutputPath
      };

      if (revealFile) {
        onProcessingStep({ msg: lang === 'es' ? `Cargando archivo de imagen ${revealFile.name}...` : `Loading image file ${revealFile.name}...`, success: true });
        
        response = await fetch('/api/decrypt', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/octet-stream',
            'X-Settings': JSON.stringify(payload),
            'X-API-Token': token
          },
          body: revealFile
        });
      } else {
        if (!revealLocalPath) {
          throw new Error(lang === 'es' ? 'Debes seleccionar la imagen portadora.' : 'You must select the carrier image file.');
        }
        onProcessingStep({ msg: lang === 'es' ? `Cargando archivo local ${revealLocalPath}...` : `Loading local file ${revealLocalPath}...`, success: true });

        response = await fetch('/api/decrypt', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-API-Token': token
          },
          body: JSON.stringify({
            filePath: revealLocalPath,
            ...payload
          })
        });
      }

      const data = await response.json();
      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Payload extraction failed.');
      }

      onProcessingStep({ msg: lang === 'es' ? 'Firma esteganográfica MIRGSTEG verificada.' : 'Steganographic MIRGSTEG signature verified.', success: true });
      
      setTimeout(() => {
        setResult({
          type: 'reveal',
          outputPath: data.restorePath,
          filename: data.filename,
          fileSize: data.fileSize,
          outputHash: data.outputHash,
          algorithm: data.algorithm || 'aes-256-gcm'
        });
        onFinishProcessing();
      }, 800);

    } catch (err) {
      onFinishProcessing(err.message);
    }
  };

  if (result) {
    return (
      <div className="success-screen" style={{ maxWidth: '650px', margin: '0 auto' }}>
        <div className="success-badge" style={{ backgroundColor: 'var(--color-cyan)', boxShadow: '0 0 20px var(--color-cyan-glow)' }}>
          <CheckCircle size={44} />
        </div>
        
        <h2 className="success-title">
          {result.type === 'hide' 
            ? (lang === 'es' ? 'CIFRADO OCULTO CON ÉXITO' : 'PAYLOAD CONCEALED SUCCESSFULLY')
            : (lang === 'es' ? 'EXTRACCIÓN COMPLETADA' : 'EXTRACTION COMPLETED')
          }
        </h2>
        <p className="success-subtitle">
          {result.type === 'hide'
            ? (lang === 'es' ? 'El archivo cifrado se ha inyectado dentro de la imagen portadora.' : 'The encrypted file has been injected inside the carrier image.')
            : (lang === 'es' ? 'Se detectó la firma stego, se extrajo el payload y se restauró el original.' : 'Stego signature detected, payload extracted, and original file restored.')
          }
        </p>

        <div className="result-card">
          {result.type === 'hide' ? (
            <>
              <div className="result-row" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="result-key">{lang === 'es' ? 'Imagen Portadora de Salida:' : 'Output Carrier Image:'}</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
                  <span className="result-val highlight" style={{ color: 'var(--color-cyan)', margin: 0 }}>
                    {result.outputPath}
                  </span>
                  <button
                    type="button"
                    style={{ background: 'none', border: 'none', color: copiedField === 'stegOut' ? 'var(--color-green)' : 'var(--text-muted)', cursor: 'pointer', flexShrink: 0, display: 'flex', alignItems: 'center' }}
                    onClick={() => copyToClipboard(result.outputPath, 'stegOut')}
                    title="Copiar ruta"
                  >
                    {copiedField === 'stegOut' ? <Check size={12} /> : <Copy size={12} />}
                  </button>
                </div>
              </div>
              <div className="result-row">
                <span className="result-key">SHA3 Entrada:</span>
                <span className="result-val" style={{ fontSize: '0.75rem', wordBreak: 'break-all' }}>{result.inputHash}</span>
              </div>
              <div className="result-row">
                <span className="result-key">Algoritmo Core:</span>
                <span className="result-val" style={{ color: 'var(--color-cyan)' }}>
                  {result.algorithm === 'mirage-c4' ? 'Mirage-C4 (1024-bit Cascade)' : 'AES-256-GCM'}
                </span>
              </div>
              <div className="result-row">
                <span className="result-key">Esteganografía:</span>
                <span className="result-val" style={{ color: 'var(--color-green)' }}>✓ Activo (Inyección EOF)</span>
              </div>
            </>
          ) : (
            <>
              <div className="result-row" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="result-key">{lang === 'es' ? 'Ruta de Restauración:' : 'Restore Path:'}</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
                  <span className="result-val highlight" style={{ color: 'var(--color-cyan)', margin: 0 }}>
                    {result.outputPath}
                  </span>
                  <button
                    type="button"
                    style={{ background: 'none', border: 'none', color: copiedField === 'stegRestore' ? 'var(--color-green)' : 'var(--text-muted)', cursor: 'pointer', flexShrink: 0, display: 'flex', alignItems: 'center' }}
                    onClick={() => copyToClipboard(result.outputPath, 'stegRestore')}
                    title="Copiar ruta"
                  >
                    {copiedField === 'stegRestore' ? <Check size={12} /> : <Copy size={12} />}
                  </button>
                </div>
              </div>
              <div className="result-row">
                <span className="result-key">{lang === 'es' ? 'Nombre del Archivo:' : 'File Name:'}</span>
                <span className="result-val">{result.filename}</span>
              </div>
              <div className="result-row">
                <span className="result-key">{lang === 'es' ? 'Tamaño:' : 'Size:'}</span>
                <span className="result-val">{(result.fileSize / 1024).toFixed(2)} KB</span>
              </div>
              <div className="result-row">
                <span className="result-key">Algoritmo Core:</span>
                <span className="result-val" style={{ color: 'var(--color-cyan)' }}>
                  {result.algorithm === 'mirage-c4' ? 'Mirage-C4 (1024-bit Cascade)' : 'AES-256-GCM'}
                </span>
              </div>
              <div className="result-row">
                <span className="result-key">Verificación de Integridad:</span>
                <span className="result-val" style={{ color: 'var(--color-green)' }}>✓ PASADA (Firma Extraída Válida)</span>
              </div>
            </>
          )}
        </div>

        <div style={{ display: 'flex', gap: '15px', justifyContent: 'center', marginTop: '30px' }}>
          <button type="button" className="btn-secondary" onClick={() => setResult(null)}>
            {lang === 'es' ? 'Realizar otra operación' : 'Perform another operation'}
          </button>
          <button type="button" className="action-btn" onClick={onBack}>
            {lang === 'es' ? 'Volver al Menú' : 'Back to Menu'}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="console-wrapper">
      <div className="console-header">
        <h2 className="console-title" style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <Image size={24} style={{ color: 'var(--color-cyan)' }} />
          {lang === 'es' ? 'CONSOLA DE ESTEGANOGRAFÍA' : 'STEGANOGRAPHY CONSOLE'}
        </h2>
      </div>

      <div style={{ display: 'flex', borderBottom: '1px solid var(--border-divider)', marginBottom: '25px', gap: '15px' }}>
        <button 
          type="button"
          onClick={() => { setActiveTab('hide'); setResult(null); }}
          style={{
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'hide' ? '2px solid var(--color-cyan)' : '2px solid transparent',
            color: activeTab === 'hide' ? 'var(--text-main)' : 'var(--text-muted)',
            padding: '10px 20px',
            fontSize: '0.95rem',
            fontWeight: 600,
            cursor: 'pointer',
            fontFamily: 'var(--font-orbitron)'
          }}
        >
          {lang === 'es' ? 'Ocultar Cifrado' : 'Conceal Payload'}
        </button>
        <button 
          type="button"
          onClick={() => { setActiveTab('reveal'); setResult(null); }}
          style={{
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'reveal' ? '2px solid var(--color-cyan)' : '2px solid transparent',
            color: activeTab === 'reveal' ? 'var(--text-main)' : 'var(--text-muted)',
            padding: '10px 20px',
            fontSize: '0.95rem',
            fontWeight: 600,
            cursor: 'pointer',
            fontFamily: 'var(--font-orbitron)'
          }}
        >
          {lang === 'es' ? 'Extraer y Descifrar' : 'Extract & Decrypt'}
        </button>
      </div>

      {activeTab === 'hide' ? (
        <form onSubmit={handleHideSubmit} className="console-grid">
          {/* Left Column: Files & Carriers */}
          <div>
            <div className="form-group">
              <label className="form-label">{lang === 'es' ? 'Archivo a Cifrar y Ocultar' : 'File to Encrypt & Hide'}</label>
              <Dropzone file={hideFile} setFile={setHideFile} onFileSelected={() => setHideLocalPath('')} lang={lang} />
            </div>

            {!hideFile && (
              <PathInput
                value={hideLocalPath}
                onChange={setHideLocalPath}
                placeholder="Ej: /Users/brx/documents/secreto.pdf"
                label={lang === 'es' ? 'O ruta del archivo local en disco' : 'Or local path of file on disk'}
              />
            )}

            <div className="form-group" style={{ marginTop: '20px' }}>
              <label className="form-label">{lang === 'es' ? 'Imagen Portadora (PNG/JPEG)' : 'Carrier Image (PNG/JPEG)'}</label>
              <Dropzone file={carrierFile} setFile={setCarrierFile} onFileSelected={() => setCarrierLocalPath('')} lang={lang} />
            </div>

            {!carrierFile && (
              <PathInput
                value={carrierLocalPath}
                onChange={setCarrierLocalPath}
                placeholder="Ej: /Users/brx/Pictures/vacaciones.png"
                label={lang === 'es' ? 'O ruta de la imagen local portadora' : 'Or local path of carrier image'}
                icon={Image}
              />
            )}
          </div>

          {/* Right Column: Passwords & Action */}
          <div>
            <div className="form-group">
              <label className="form-label">{lang === 'es' ? 'Algoritmo Core' : 'Core Algorithm'}</label>
              <select
                className="form-input"
                style={{ paddingLeft: '14px', background: 'rgba(0, 0, 0, 0.35)', color: 'var(--text-light)', border: '1px solid rgba(255, 255, 255, 0.15)', cursor: 'pointer' }}
                value={hideAlgorithm}
                onChange={(e) => setHideAlgorithm(e.target.value)}
              >
                <option value="aes-256-gcm">AES-256-GCM (Standard)</option>
                <option value="mirage-c4">Mirage-C4 (1024-bit Cascade)</option>
              </select>
              <div style={{
                marginTop: '8px',
                padding: '12px',
                backgroundColor: 'rgba(255, 255, 255, 0.02)',
                border: '1px dashed rgba(255, 255, 255, 0.08)',
                borderRadius: '8px',
                fontSize: '0.78rem',
                lineHeight: '1.4',
                color: 'var(--text-muted)'
              }}>
                {hideAlgorithm === 'mirage-c4' 
                  ? (lang === 'es' ? 'Mirage-C4 une en cascada Camellia-256-CTR, ARIA-256-CTR, ChaCha20 y AES-256-GCM. Deriva claves individuales de 256 bits para cada capa con Scrypt.' : 'Mirage-C4 chains Camellia-256-CTR, ARIA-256-CTR, ChaCha20, and AES-256-GCM. Derives individual 256-bit keys via Scrypt.')
                  : (lang === 'es' ? 'AES-256-GCM es el estándar. Cifrado simétrico autenticado de alta velocidad.' : 'AES-256-GCM is standard. High-speed authenticated symmetric cipher.')
                }
              </div>
            </div>

            <div className="form-group">
              <label className="form-label">{lang === 'es' ? 'Contraseña Clave' : 'Master Password'}</label>
              <div className="form-input-wrapper">
                <Key className="form-input-icon" size={18} />
                <input
                  type={showHidePassword ? "text" : "password"}
                  className="form-input"
                  value={hidePassword}
                  onChange={(e) => setHidePassword(e.target.value)}
                  placeholder={lang === 'es' ? 'Escribe la contraseña de cifrado...' : 'Type your encryption password...'}
                  required
                />
                <button
                  type="button"
                  style={{ position: 'absolute', right: '14px', background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
                  onClick={() => setShowHidePassword(!showHidePassword)}
                >
                  {showHidePassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            <PathInput
              value={hideOutputPath}
              onChange={setHideOutputPath}
              placeholder={lang === 'es' ? 'Ej: /Users/brx/Desktop/oculto.png' : 'E.g., /Users/brx/Desktop/hidden.png'}
              label={lang === 'es' ? 'Ruta de la Imagen de Salida (Opcional)' : 'Output Image Path (Optional)'}
              icon={Image}
            />

            <div className="action-btn-wrapper" style={{ marginTop: '30px' }}>
              <button 
                type="submit" 
                className="action-btn"
                disabled={!hidePassword || (!hideFile && !hideLocalPath)}
                style={{ backgroundColor: 'var(--color-cyan)', boxShadow: '0 0 15px var(--color-cyan-glow)' }}
              >
                <Lock size={20} />
                {lang === 'es' ? 'Ocultar y Cifrar' : 'Conceal & Encrypt'}
              </button>
            </div>
          </div>
        </form>
      ) : (
        <form onSubmit={handleRevealSubmit} className="console-grid">
          {/* Left Column: Stego Carrier File */}
          <div>
            <div className="form-group">
              <label className="form-label">{lang === 'es' ? 'Imagen con Payload Oculto' : 'Image with Hidden Payload'}</label>
              <Dropzone file={revealFile} setFile={setRevealFile} onFileSelected={() => setRevealLocalPath('')} lang={lang} />
            </div>

            {!revealFile && (
              <PathInput
                value={revealLocalPath}
                onChange={setRevealLocalPath}
                placeholder="Ej: /Users/brx/Desktop/oculto.png"
                label={lang === 'es' ? 'O ruta de la imagen local' : 'Or local path of stego image'}
                icon={Image}
              />
            )}
          </div>

          {/* Right Column: Password & Action */}
          <div>
            <div className="form-group">
              <label className="form-label">{lang === 'es' ? 'Contraseña Clave' : 'Master Password'}</label>
              <div className="form-input-wrapper">
                <Key className="form-input-icon" size={18} />
                <input
                  type={showRevealPassword ? "text" : "password"}
                  className="form-input"
                  value={revealPassword}
                  onChange={(e) => setRevealPassword(e.target.value)}
                  placeholder={lang === 'es' ? 'Ingresa la contraseña principal...' : 'Enter primary password...'}
                  required
                />
                <button
                  type="button"
                  style={{ position: 'absolute', right: '14px', background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
                  onClick={() => setShowRevealPassword(!showRevealPassword)}
                >
                  {showRevealPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            <PathInput
              value={revealOutputPath}
              onChange={setRevealOutputPath}
              placeholder={lang === 'es' ? 'Ej: /Users/brx/Downloads' : 'E.g., /Users/brx/Downloads'}
              label={lang === 'es' ? 'Directorio de Restauración (Opcional)' : 'Restore Directory (Optional)'}
            />

            <div className="action-btn-wrapper" style={{ marginTop: '30px' }}>
              <button 
                type="submit" 
                className="action-btn"
                disabled={!revealPassword || (!revealFile && !revealLocalPath)}
                style={{ backgroundColor: 'var(--color-cyan)', boxShadow: '0 0 15px var(--color-cyan-glow)' }}
              >
                <Unlock size={20} />
                {lang === 'es' ? 'Extraer y Descifrar' : 'Extract & Decrypt'}
              </button>
            </div>
          </div>
        </form>
      )}
    </div>
  );
}
