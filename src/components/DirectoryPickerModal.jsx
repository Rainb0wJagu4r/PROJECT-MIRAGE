import React, { useState, useEffect } from 'react';
import { 
  Folder, 
  File, 
  HardDrive, 
  ArrowUp, 
  Home, 
  Download, 
  Image as ImageIcon, 
  FileText, 
  Monitor, 
  X, 
  Check, 
  RefreshCw, 
  Search,
  FolderPlus
} from 'lucide-react';
import tokenData from '../token.json';

export default function DirectoryPickerModal({
  isOpen,
  onClose,
  onSelect,
  initialPath = '',
  mode = 'directory', // 'directory' | 'file'
  title = 'Explorador de Archivos y Carpetas'
}) {
  const [currentPath, setCurrentPath] = useState(initialPath || '');
  const [parentPath, setParentPath] = useState(null);
  const [items, setItems] = useState([]);
  const [shortcuts, setShortcuts] = useState([]);
  const [drives, setDrives] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [filterText, setFilterText] = useState('');
  const [selectedItem, setSelectedItem] = useState(null);

  // Load shortcuts on mount
  useEffect(() => {
    if (!isOpen) return;
    fetch('/api/system-shortcuts', {
      headers: { 'X-API-Token': tokenData.token }
    })
      .then(res => res.json())
      .then(data => {
        if (data.shortcuts) setShortcuts(data.shortcuts);
        if (data.drives) setDrives(data.drives);
      })
      .catch(err => console.error('Failed to load shortcuts:', err));
  }, [isOpen]);

  // Load directory items
  const loadDirectory = async (targetPath) => {
    setIsLoading(true);
    setSelectedItem(null);
    try {
      const url = targetPath 
        ? `/api/browse-dir?path=${encodeURIComponent(targetPath)}`
        : '/api/browse-dir';
      const res = await fetch(url, {
        headers: { 'X-API-Token': tokenData.token }
      });
      const data = await res.json();
      if (data.currentPath) {
        setCurrentPath(data.currentPath);
        setParentPath(data.parentPath);
        setItems(data.items || []);
      }
    } catch (err) {
      console.error('Failed to browse directory:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      loadDirectory(initialPath);
    }
  }, [isOpen, initialPath]);

  if (!isOpen) return null;

  const handleItemClick = (item) => {
    if (item.isDirectory) {
      loadDirectory(item.path);
    } else {
      setSelectedItem(item);
    }
  };

  const handleConfirm = () => {
    if (mode === 'file') {
      if (selectedItem) {
        onSelect(selectedItem.path);
        onClose();
      } else {
        onSelect(currentPath);
        onClose();
      }
    } else {
      // Directory mode
      onSelect(currentPath);
      onClose();
    }
  };

  const filteredItems = items.filter(item => 
    item.name.toLowerCase().includes(filterText.toLowerCase())
  );

  return (
    <div className="modal-backdrop animate-fade-in" style={{
      position: 'fixed',
      top: 0,
      left: 0,
      width: '100%',
      height: '100%',
      background: 'rgba(0, 0, 0, 0.85)',
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      zIndex: 1100,
      padding: '20px'
    }}>
      <div className="modal-card" style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border)',
        borderRadius: '12px',
        width: '100%',
        maxWidth: '850px',
        height: '75vh',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        boxShadow: '0 20px 60px rgba(0, 0, 0, 0.9)'
      }}>
        {/* MODAL HEADER */}
        <div style={{
          padding: '16px 20px',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <FolderPlus size={20} style={{ color: 'var(--color-primary)' }} />
            <h3 style={{ fontFamily: 'var(--font-orbitron)', fontSize: '1rem', margin: 0 }}>
              {title}
            </h3>
          </div>
          <button type="button" className="btn-icon" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        {/* BREADCRUMB & CONTROLS BAR */}
        <div style={{
          padding: '10px 16px',
          background: 'var(--bg-panel)',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          gap: '10px',
          alignItems: 'center'
        }}>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => parentPath && loadDirectory(parentPath)}
            disabled={!parentPath || isLoading}
            style={{ padding: '6px 12px' }}
            title="Subir un nivel"
          >
            <ArrowUp size={16} />
          </button>

          <input
            type="text"
            className="form-input"
            value={currentPath}
            onChange={(e) => setCurrentPath(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && loadDirectory(currentPath)}
            style={{ flex: 1, fontSize: '0.8rem', padding: '6px 12px', fontFamily: 'var(--font-mono)' }}
          />

          <button
            type="button"
            className="btn-secondary"
            onClick={() => loadDirectory(currentPath)}
            disabled={isLoading}
            style={{ padding: '6px 12px' }}
            title="Refrescar"
          >
            <RefreshCw size={14} className={isLoading ? 'spin' : ''} />
          </button>
        </div>

        {/* MAIN EXPLORER BODY: SIDEBAR + FILES */}
        <div style={{ display: 'flex', flex: 1, minHeight: 0 }}>
          {/* SHORTCUTS SIDEBAR */}
          <div style={{
            width: '210px',
            borderRight: '1px solid var(--border)',
            background: 'rgba(0,0,0,0.2)',
            padding: '12px',
            display: 'flex',
            flexDirection: 'column',
            gap: '16px',
            overflowY: 'auto'
          }}>
            <div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '8px', letterSpacing: '0.5px' }}>
                Accesos Rápidos
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                {shortcuts.map((sc, i) => (
                  <div
                    key={i}
                    onClick={() => loadDirectory(sc.path)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                      padding: '6px 10px',
                      borderRadius: '6px',
                      fontSize: '0.8rem',
                      cursor: 'pointer',
                      background: currentPath === sc.path ? 'rgba(139, 92, 246, 0.15)' : 'transparent',
                      color: currentPath === sc.path ? 'var(--color-primary)' : 'var(--text-main)'
                    }}
                  >
                    {sc.icon === 'desktop' && <Monitor size={14} />}
                    {sc.icon === 'document' && <FileText size={14} />}
                    {sc.icon === 'download' && <Download size={14} />}
                    {sc.icon === 'image' && <ImageIcon size={14} />}
                    {sc.icon === 'home' && <Home size={14} />}
                    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {sc.name}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {drives.length > 0 && (
              <div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '8px', letterSpacing: '0.5px' }}>
                  Unidades de Disco
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  {drives.map((d, i) => (
                    <div
                      key={i}
                      onClick={() => loadDirectory(d.path)}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px',
                        padding: '6px 10px',
                        borderRadius: '6px',
                        fontSize: '0.8rem',
                        cursor: 'pointer',
                        background: currentPath === d.path ? 'rgba(139, 92, 246, 0.15)' : 'transparent',
                        color: currentPath === d.path ? 'var(--color-primary)' : 'var(--text-main)'
                      }}
                    >
                      <HardDrive size={14} style={{ color: 'var(--color-cyan)' }} />
                      <span>{d.name}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* FILES & FOLDERS LIST */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
            {/* Search Filter */}
            <div style={{ padding: '8px 14px', borderBottom: '1px solid var(--border-divider)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Search size={14} style={{ color: 'var(--text-muted)' }} />
              <input
                type="text"
                placeholder="Filtrar archivos en esta carpeta..."
                value={filterText}
                onChange={(e) => setFilterText(e.target.value)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--text-main)',
                  fontSize: '0.8rem',
                  outline: 'none',
                  width: '100%'
                }}
              />
            </div>

            {/* Item Table */}
            <div style={{ flex: 1, overflowY: 'auto', padding: '6px' }}>
              {isLoading ? (
                <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                  <RefreshCw className="spin" size={24} style={{ marginBottom: '8px' }} />
                  <div style={{ fontSize: '0.85rem' }}>Cargando contenido...</div>
                </div>
              ) : filteredItems.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                  Carpeta vacía o sin coincidencias de filtro.
                </div>
              ) : (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: '6px' }}>
                  {filteredItems.map((item, idx) => (
                    <div
                      key={idx}
                      onClick={() => handleItemClick(item)}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px',
                        padding: '8px 10px',
                        borderRadius: '6px',
                        border: selectedItem?.path === item.path ? '1px solid var(--color-primary)' : '1px solid transparent',
                        background: selectedItem?.path === item.path ? 'rgba(139, 92, 246, 0.15)' : 'rgba(255, 255, 255, 0.02)',
                        cursor: 'pointer',
                        transition: 'all 0.15s ease'
                      }}
                      onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255, 255, 255, 0.05)'}
                      onMouseLeave={(e) => e.currentTarget.style.background = selectedItem?.path === item.path ? 'rgba(139, 92, 246, 0.15)' : 'rgba(255, 255, 255, 0.02)'}
                    >
                      {item.isDirectory ? (
                        <Folder size={18} style={{ color: '#8b5cf6', flexShrink: 0 }} />
                      ) : (
                        <File size={18} style={{ color: '#06b6d4', flexShrink: 0 }} />
                      )}
                      <div style={{ minWidth: 0, flex: 1 }}>
                        <div style={{ fontSize: '0.8rem', fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {item.name}
                        </div>
                        {!item.isDirectory && (
                          <div style={{ fontSize: '0.68rem', color: 'var(--text-dark)' }}>
                            {(item.size / 1024).toFixed(1)} KB
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* FOOTER SELECTION BAR */}
        <div style={{
          padding: '14px 20px',
          borderTop: '1px solid var(--border)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          background: 'var(--bg-panel)'
        }}>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '500px' }}>
            <strong>Seleccionado:</strong> {selectedItem ? selectedItem.path : currentPath}
          </div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <button type="button" className="btn-secondary" onClick={onClose}>
              Cancelar
            </button>
            <button type="button" className="btn-primary" onClick={handleConfirm} style={{ padding: '8px 18px' }}>
              <Check size={16} /> Seleccionar
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
