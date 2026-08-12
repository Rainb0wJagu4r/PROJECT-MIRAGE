import React, { useState, useEffect, useRef } from 'react';
import { Folder, File, HelpCircle } from 'lucide-react';

export default function PathInput({ 
  value, 
  onChange, 
  placeholder = 'Ej: /Users/usuario/documento.txt',
  label, 
  icon: Icon = Folder 
}) {
  const [suggestions, setSuggestions] = useState([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const containerRef = useRef(null);

  // Fetch suggestions from local Express API
  useEffect(() => {
    if (!showSuggestions) return;

    const timer = setTimeout(async () => {
      try {
        const response = await fetch(`/api/autocomplete?path=${encodeURIComponent(value || '')}`);
        const data = await response.json();
        if (data && data.items) {
          setSuggestions(data.items);
        } else {
          setSuggestions([]);
        }
      } catch (err) {
        console.error('Failed to load autocomplete items:', err);
      }
    }, 150); // slight debounce

    return () => clearTimeout(timer);
  }, [value, showSuggestions]);

  // Handle outside clicks to close suggestion box
  useEffect(() => {
    const handleOutsideClick = (e) => {
      if (containerRef.current && !containerRefRef.current.contains(e.target)) {
        setShowSuggestions(false);
      }
    };
    document.addEventListener('mousedown', handleOutsideClick);
    return () => document.removeEventListener('mousedown', handleOutsideClick);
  }, []);

  const containerRefRef = containerRef; // align reference name

  const handleSuggestionClick = (item) => {
    onChange(item.path + (item.isDirectory ? '/' : ''));
    if (!item.isDirectory) {
      setShowSuggestions(false);
    }
  };

  return (
    <div className="form-group" ref={containerRef}>
      {label && <label className="form-label">{label}</label>}
      <div className="form-input-wrapper">
        <Icon className="form-input-icon" size={18} />
        <input
          type="text"
          className="form-input"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onFocus={() => setShowSuggestions(true)}
          placeholder={placeholder}
        />
      </div>

      {showSuggestions && suggestions.length > 0 && (
        <div className="autocomplete-popover">
          {suggestions.map((item, idx) => (
            <div 
              key={idx}
              className="autocomplete-item"
              onClick={() => handleSuggestionClick(item)}
            >
              {item.isDirectory ? (
                <Folder size={14} style={{ color: '#8b5cf6', flexShrink: 0 }} />
              ) : (
                <File size={14} style={{ color: '#06b6d4', flexShrink: 0 }} />
              )}
              <div style={{ display: 'flex', flexDirection: 'column', minWidth: 0, flex: 1 }}>
                <span style={{ fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {item.name}
                </span>
                <span className="item-path" title={item.path}>
                  {item.path}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
