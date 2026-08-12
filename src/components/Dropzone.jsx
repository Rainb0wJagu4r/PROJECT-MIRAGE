import React, { useState, useRef } from 'react';
import { UploadCloud, FileText, Trash2 } from 'lucide-react';

export default function Dropzone({ file, setFile, onFileSelected }) {
  const [dragging, setDragging] = useState(false);
  const fileInputRef = useRef(null);

  const handleDragOver = (e) => {
    e.preventDefault();
    setDragging(true);
  };

  const handleDragLeave = () => {
    setDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragging(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const selectedFile = e.dataTransfer.files[0];
      setFile(selectedFile);
      if (onFileSelected) onFileSelected(selectedFile);
    }
  };

  const handleClick = () => {
    fileInputRef.current.click();
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      const selectedFile = e.target.files[0];
      setFile(selectedFile);
      if (onFileSelected) onFileSelected(selectedFile);
    }
  };

  const handleClear = (e) => {
    e.stopPropagation();
    setFile(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
    if (onFileSelected) onFileSelected(null);
  };

  // Helper to format file size
  const formatSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div>
      <div 
        className={`dropzone-container ${dragging ? 'dragging' : ''}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={handleClick}
      >
        <input 
          type="file"
          ref={fileInputRef}
          onChange={handleFileChange}
          style={{ display: 'none' }}
        />
        <UploadCloud className="dropzone-icon" />
        <div className="dropzone-text-primary">
          Arrastra y suelta tu archivo aquí
        </div>
        <div className="dropzone-text-secondary">
          o haz clic para explorar tus archivos locales
        </div>
      </div>

      {file && (
        <div className="file-info-box">
          <div className="file-details">
            <FileText className="file-icon" />
            <div className="file-meta">
              <div className="file-name" title={file.name}>{file.name}</div>
              <div className="file-size">{formatSize(file.size || 0)}</div>
            </div>
          </div>
          <button className="remove-file-btn" onClick={handleClear} title="Remover archivo">
            <Trash2 size={16} />
          </button>
        </div>
      )}
    </div>
  );
}
