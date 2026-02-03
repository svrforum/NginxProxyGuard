import React, { useState, useRef, useEffect } from 'react';
import type { TagInputProps } from '../types';

export function TagInput({ values, onChange, placeholder, fetchSuggestions, className, helpText }: TagInputProps) {
  const [inputValue, setInputValue] = useState('');
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [loading, setLoading] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(-1);
  const [pendingSelections, setPendingSelections] = useState<string[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const addTag = (tag: string) => {
    const trimmed = tag.trim();
    if (trimmed && !values.includes(trimmed)) {
      onChange([...values, trimmed]);
    }
    setInputValue('');
    setSelectedIndex(-1);
  };

  const addMultipleTags = (tags: string[]) => {
    const newTags = tags.filter(t => t.trim() && !values.includes(t.trim()));
    if (newTags.length > 0) {
      onChange([...values, ...newTags]);
    }
    setPendingSelections([]);
    setInputValue('');
    setSuggestions([]);
    setShowSuggestions(false);
  };

  const removeTag = (index: number) => {
    onChange(values.filter((_, i) => i !== index));
  };

  const togglePendingSelection = (suggestion: string) => {
    setPendingSelections(prev => {
      if (prev.includes(suggestion)) {
        return prev.filter(s => s !== suggestion);
      } else {
        return [...prev, suggestion];
      }
    });
  };

  const handleInputChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const newValue = e.target.value;
    setInputValue(newValue);
    setSelectedIndex(-1);
    setPendingSelections([]);

    if (fetchSuggestions && newValue.length >= 1) {
      setLoading(true);
      try {
        const results = await fetchSuggestions(newValue);
        setSuggestions((results || []).filter(s => !values.includes(s)));
        setShowSuggestions(true);
      } catch {
        setSuggestions([]);
      } finally {
        setLoading(false);
      }
    } else {
      setSuggestions([]);
      setShowSuggestions(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (showSuggestions && suggestions.length > 0) {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSelectedIndex(prev => {
          const next = prev < suggestions.length - 1 ? prev + 1 : 0;
          listRef.current?.children[next]?.scrollIntoView({ block: 'nearest' });
          return next;
        });
        return;
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSelectedIndex(prev => {
          const next = prev > 0 ? prev - 1 : suggestions.length - 1;
          listRef.current?.children[next]?.scrollIntoView({ block: 'nearest' });
          return next;
        });
        return;
      } else if (e.key === 'Enter' && selectedIndex >= 0) {
        e.preventDefault();
        togglePendingSelection(suggestions[selectedIndex]);
        return;
      } else if (e.key === 'Escape') {
        if (pendingSelections.length > 0) {
          setPendingSelections([]);
        } else {
          setShowSuggestions(false);
        }
        setSelectedIndex(-1);
        return;
      }
    }

    if ((e.key === 'Enter' || e.key === ' ' || e.key === ',') && inputValue.trim() && !showSuggestions) {
      e.preventDefault();
      addTag(inputValue);
    } else if (e.key === 'Enter' && pendingSelections.length > 0) {
      e.preventDefault();
      addMultipleTags(pendingSelections);
    } else if (e.key === 'Backspace' && !inputValue && values.length > 0) {
      removeTag(values.length - 1);
    }
  };

  const handleItemClick = (suggestion: string) => {
    togglePendingSelection(suggestion);
  };

  const handleApplySelection = () => {
    if (pendingSelections.length > 0) {
      addMultipleTags(pendingSelections);
    }
    inputRef.current?.focus();
  };

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        if (pendingSelections.length > 0) {
          addMultipleTags(pendingSelections);
        }
        setShowSuggestions(false);
        setSelectedIndex(-1);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pendingSelections, values]);

  return (
    <div className="relative" ref={containerRef}>
      <div
        className={`flex flex-wrap gap-1 p-1.5 min-h-[38px] border rounded-lg bg-white dark:bg-slate-700 dark:border-slate-600 focus-within:ring-2 focus-within:ring-primary-500 ${className}`}
        onClick={() => inputRef.current?.focus()}
      >
        {values.map((tag, index) => (
          <span
            key={index}
            className="inline-flex items-center gap-1 px-2 py-0.5 bg-primary-100 dark:bg-primary-900/30 text-primary-800 dark:text-primary-300 rounded text-xs font-medium"
          >
            {tag}
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); removeTag(index); }}
              className="hover:text-primary-600 dark:hover:text-primary-200"
            >
              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </span>
        ))}
        <input
          ref={inputRef}
          type="text"
          value={inputValue}
          onChange={handleInputChange}
          onKeyDown={handleKeyDown}
          onFocus={() => suggestions.length > 0 && setShowSuggestions(true)}
          placeholder={values.length === 0 ? placeholder : ''}
          className="flex-1 min-w-[100px] px-1 py-0.5 text-sm bg-transparent border-none outline-none dark:text-white dark:placeholder-slate-400"
        />
        {loading && (
          <div className="flex items-center pr-1">
            <div className="w-4 h-4 border-2 border-primary-500 border-t-transparent rounded-full animate-spin"></div>
          </div>
        )}
      </div>
      {helpText && (
        <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">{helpText}</p>
      )}
      {showSuggestions && suggestions.length > 0 && (
        <div className="absolute z-50 w-full mt-1 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-600 rounded-lg shadow-lg overflow-hidden">
          <ul ref={listRef} className="max-h-48 overflow-y-auto">
            {suggestions.map((suggestion, index) => (
              <li
                key={index}
                onClick={() => handleItemClick(suggestion)}
                className={`flex items-center gap-2 px-3 py-2 text-sm cursor-pointer transition-colors ${
                  index === selectedIndex
                    ? 'bg-primary-100 dark:bg-primary-900/40 text-primary-800 dark:text-primary-200'
                    : 'hover:bg-slate-100 dark:hover:bg-slate-700 dark:text-slate-300'
                }`}
              >
                <input
                  type="checkbox"
                  checked={pendingSelections.includes(suggestion)}
                  readOnly
                  className="w-4 h-4 rounded border-slate-300 dark:border-slate-600 text-primary-600 focus:ring-primary-500 pointer-events-none"
                />
                <span className="truncate flex-1">{suggestion}</span>
              </li>
            ))}
          </ul>
          {pendingSelections.length > 0 && (
            <div className="flex items-center justify-between px-3 py-2 border-t border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900/50">
              <span className="text-xs text-slate-500 dark:text-slate-400">
                {pendingSelections.length}개 선택됨
              </span>
              <button
                type="button"
                onClick={handleApplySelection}
                className="px-3 py-1 text-xs font-medium text-white bg-primary-600 hover:bg-primary-700 rounded transition-colors"
              >
                추가
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
