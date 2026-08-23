import React from 'react';
import { 
  ShieldAlert, 
  Cpu, 
  Trash2, 
  Clock, 
  Shuffle, 
  Binary, 
  Database,
  Lock,
  FileWarning
} from 'lucide-react';
import PathInput from './PathInput';

const optTrans = {
  es: {
    header: "BLINDAJE Y SEGURIDAD ADICIONAL",
    metaTitle: "Eliminación de Metadatos",
    metaDesc: "Limpia EXIF, GPS, cámara y autor de imágenes JPEG/PNG antes de cifrar.",
    sizeTitle: "Ofuscación de Tamaño (Signal-style)",
    sizeDesc: "Agrega ruido exponencial de bytes aleatorios. Hace imposible deducir el tamaño real.",
    hwTitle: "Pepper de Hardware (KDF Lock)",
    hwDesc: "Vincula el cifrado a esta máquina física usando su identificador de hardware único (UUID).",
    ttlTitle: "Tiempo de Vida Limitado (TTL)",
    ttlDesc: "El archivo expira y se auto-destruye tras el tiempo configurado.",
    ttlLabel: "Tiempo de expiración (en horas)",
    ttlPlaceholder: "Ej: 1 hora, 0.5 (30 mins), 24 (1 día)",
    duressTitle: "Modo Duress (Contraseña Señuelo)",
    duressDesc: "Cifra un archivo señuelo. Si se introduce la contraseña señuelo al descifrar, se restaurará el señuelo.",
    duressPassLabel: "Contraseña del Señuelo (Distinta a la principal)",
    duressPassPlaceholder: "Contraseña del señuelo...",
    decoyPathLabel: "Ruta del Archivo Señuelo (Si se deja vacío, se generará una advertencia)",
    decoyPathPlaceholder: "Ruta del archivo señuelo en disco...",
    splitTitle: "Fragmentación de Datos (2-of-3 Split)",
    splitDesc: "Divide el archivo cifrado en 3 fragmentos matemáticos. Requiere cualquier combinación de 2 de ellos para descifrar.",
    shredTitle: "Destrucción del Original (Shredder)",
    shredDesc: "Sobrescribe el archivo original en disco en múltiples pasadas de datos aleatorios antes de borrarlo.",
    shredPassesLabel: "Pasadas de Sobrescritura",
    shredOption1: "1 pasada (Rápido)",
    shredOption3: "3 pasadas (Estándar Seguro)",
    shredOption7: "7 pasadas (Sobrescritura Profunda / Alta Seguridad)",
  },
  en: {
    header: "ADDITIONAL ARMOR & SECURITY",
    metaTitle: "Metadata Scrubbing",
    metaDesc: "Clean EXIF, GPS, camera and author tags from JPEG/PNG images before encrypting.",
    sizeTitle: "Size Obfuscation (Signal-style)",
    sizeDesc: "Appends exponential random padding bytes. Prevents sizing analysis.",
    hwTitle: "Hardware Pepper Lock (KDF Lock)",
    hwDesc: "Binds the encryption to this physical machine using its unique hardware UUID.",
    ttlTitle: "Time-to-Live (TTL)",
    ttlDesc: "The file expires and auto-destructs after the configured duration.",
    ttlLabel: "Expiration time (in hours)",
    ttlPlaceholder: "E.g., 1 hour, 0.5 (30 mins), 24 (1 day)",
    duressTitle: "Duress Mode (Decoy Password)",
    duressDesc: "Encrypts a decoy file. Entering the decoy password during decryption restores the decoy.",
    duressPassLabel: "Decoy Password (Must be different from primary)",
    duressPassPlaceholder: "Decoy password...",
    decoyPathLabel: "Decoy File Path (If left blank, a warning document will be generated)",
    decoyPathPlaceholder: "Path to decoy file on disk...",
    splitTitle: "Data Fragmentation (2-of-3 Split)",
    splitDesc: "Splits the encrypted file into 3 mathematical shares. Any 2 are required to decrypt.",
    shredTitle: "Secure Shredder (Original File Wiped)",
    shredDesc: "Overwrites original file on disk with random passes before unlinking permanently.",
    shredPassesLabel: "Overwrite Passes",
    shredOption1: "1 pass (Fast)",
    shredOption3: "3 passes (Secure Standard)",
    shredOption7: "7 passes (Deep Overwrite / High Security)",
  }
};

export default function AdvancedOptions({ settings, setSetting, lang = 'es' }) {
  const t = optTrans[lang] || optTrans.es;
  
  const toggleSetting = (key) => {
    setSetting(key, !settings[key]);
  };

  return (
    <div className="armor-options-container">
      <h3 style={{ fontFamily: 'var(--font-orbitron)', fontSize: '1rem', letterSpacing: '0.5px', marginBottom: '8px', color: 'var(--text-muted)' }}>
        {t.header}
      </h3>

      {/* 1. Metadata Scrubbing */}
      <div className={`armor-card ${settings.metadataScrubEnabled ? 'active' : ''}`}>
        <div className="armor-row" onClick={() => toggleSetting('metadataScrubEnabled')}>
          <div className="armor-info">
            <Trash2 className="armor-icon" size={20} />
            <div>
              <div className="armor-label-title">{t.metaTitle}</div>
              <div className="armor-label-desc">{t.metaDesc}</div>
            </div>
          </div>
          <div className="switch-control">
            <div className="switch-knob" />
          </div>
        </div>
      </div>

      {/* 2. Signal-style Size Obfuscation */}
      <div className={`armor-card ${settings.sizeObfuscationEnabled ? 'active' : ''}`}>
        <div className="armor-row" onClick={() => toggleSetting('sizeObfuscationEnabled')}>
          <div className="armor-info">
            <Shuffle className="armor-icon" size={20} />
            <div>
              <div className="armor-label-title">{t.sizeTitle}</div>
              <div className="armor-label-desc">{t.sizeDesc}</div>
            </div>
          </div>
          <div className="switch-control">
            <div className="switch-knob" />
          </div>
        </div>
      </div>

      {/* 3. Hardware Pepper Lock */}
      <div className={`armor-card ${settings.hardwareLockEnabled ? 'active' : ''}`}>
        <div className="armor-row" onClick={() => toggleSetting('hardwareLockEnabled')}>
          <div className="armor-info">
            <Cpu className="armor-icon" size={20} />
            <div>
              <div className="armor-label-title">{t.hwTitle}</div>
              <div className="armor-label-desc">{t.hwDesc}</div>
            </div>
          </div>
          <div className="switch-control">
            <div className="switch-knob" />
          </div>
        </div>
      </div>

      {/* 4. TTL Expiration */}
      <div className={`armor-card ${settings.ttlEnabled ? 'active' : ''}`}>
        <div className="armor-row" onClick={() => toggleSetting('ttlEnabled')}>
          <div className="armor-info">
            <Clock className="armor-icon" size={20} />
            <div>
              <div className="armor-label-title">{t.ttlTitle}</div>
              <div className="armor-label-desc">{t.ttlDesc}</div>
            </div>
          </div>
          <div className="switch-control">
            <div className="switch-knob" />
          </div>
        </div>
        {settings.ttlEnabled && (
          <div className="armor-subfields">
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">{t.ttlLabel}</label>
              <div className="form-input-wrapper">
                <Clock className="form-input-icon" size={18} />
                <input 
                  type="number" 
                  step="0.1" 
                  min="0.1"
                  className="form-input" 
                  value={settings.ttlValue} 
                  onChange={(e) => setSetting('ttlValue', e.target.value)}
                  placeholder={t.ttlPlaceholder}
                />
              </div>
            </div>
          </div>
        )}
      </div>

      {/* 5. Duress Mode */}
      <div className={`armor-card ${settings.duressEnabled ? 'active' : ''}`}>
        <div className="armor-row" onClick={() => toggleSetting('duressEnabled')}>
          <div className="armor-info">
            <ShieldAlert className="armor-icon" size={20} />
            <div>
              <div className="armor-label-title">{t.duressTitle}</div>
              <div className="armor-label-desc">{t.duressDesc}</div>
            </div>
          </div>
          <div className="switch-control">
            <div className="switch-knob" />
          </div>
        </div>
        {settings.duressEnabled && (
          <div className="armor-subfields" style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">{t.duressPassLabel}</label>
              <div className="form-input-wrapper">
                <Lock className="form-input-icon" size={18} />
                <input 
                  type="password" 
                  className="form-input" 
                  value={settings.duressPassword} 
                  onChange={(e) => setSetting('duressPassword', e.target.value)}
                  placeholder={t.duressPassPlaceholder}
                />
              </div>
              {settings.duressPassword && settings.duressPassword.length < 10 && (
                <div style={{ color: 'var(--color-red)', fontSize: '0.72rem', marginTop: '6px', fontFamily: 'var(--font-mono)' }}>
                  ⚠️ {lang === 'es' ? 'La contraseña del señuelo debe tener al menos 10 caracteres.' : 'Decoy password must be at least 10 characters.'}
                </div>
              )}
            </div>

            <PathInput
              value={settings.duressDecoyPath}
              onChange={(val) => setSetting('duressDecoyPath', val)}
              placeholder={t.decoyPathPlaceholder}
              label={t.decoyPathLabel}
              icon={FileWarning}
            />
          </div>
        )}
      </div>

      {/* 6. Split Fragment 2-of-3 */}
      <div className={`armor-card ${settings.splitFragmentEnabled ? 'active' : ''}`}>
        <div className="armor-row" onClick={() => toggleSetting('splitFragmentEnabled')}>
          <div className="armor-info">
            <Binary className="armor-icon" size={20} />
            <div>
              <div className="armor-label-title">{t.splitTitle}</div>
              <div className="armor-label-desc">{t.splitDesc}</div>
            </div>
          </div>
          <div className="switch-control">
            <div className="switch-knob" />
          </div>
        </div>
      </div>

      {/* 7. File Shredder */}
      <div className={`armor-card ${settings.shredOriginalEnabled ? 'active' : ''}`}>
        <div className="armor-row" onClick={() => toggleSetting('shredOriginalEnabled')}>
          <div className="armor-info">
            <Database className="armor-icon" size={20} />
            <div>
              <div className="armor-label-title">{t.shredTitle}</div>
              <div className="armor-label-desc">{t.shredDesc}</div>
            </div>
          </div>
          <div className="switch-control">
            <div className="switch-knob" />
          </div>
        </div>
        {settings.shredOriginalEnabled && (
          <div className="armor-subfields">
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">{t.shredPassesLabel}</label>
              <select 
                className="form-input" 
                style={{ paddingLeft: '14px' }} 
                value={settings.shredPasses}
                onChange={(e) => setSetting('shredPasses', e.target.value)}
              >
                <option value="1">{t.shredOption1}</option>
                <option value="3">{t.shredOption3}</option>
                <option value="7">{t.shredOption7}</option>
              </select>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
