import { useState, useRef, useEffect, useLayoutEffect } from 'react'
import { createPortal } from 'react-dom'
import { useTranslation } from 'react-i18next'

interface HelpTipProps {
    /** Translation key for the content */
    contentKey?: string
    /** Direct content string (fallback if key not provided) */
    content?: string
    /** Translation namespace (default: 'proxyHost') */
    ns?: string
    /** Custom class for the trigger button */
    className?: string
}

export function HelpTip({ contentKey, content, ns = 'proxyHost', className = '' }: HelpTipProps) {
    const { t } = useTranslation(ns)
    const [isOpen, setIsOpen] = useState(false)
    const [position, setPosition] = useState<{ top: number; left: number; placement: 'top' | 'bottom' } | null>(null)
    const tooltipRef = useRef<HTMLDivElement>(null)
    const buttonRef = useRef<HTMLButtonElement>(null)
    // Timer for hover interactions
    const timerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)

    // Close on click outside
    useEffect(() => {
        function handleClickOutside(event: MouseEvent) {
            if (
                tooltipRef.current &&
                !tooltipRef.current.contains(event.target as Node) &&
                buttonRef.current &&
                !buttonRef.current.contains(event.target as Node)
            ) {
                setIsOpen(false)
            }
        }
        document.addEventListener('mousedown', handleClickOutside)
        return () => document.removeEventListener('mousedown', handleClickOutside)
    }, [])

    // Calculate position
    useLayoutEffect(() => {
        if (!isOpen || !buttonRef.current) {
            return
        }

        const updatePosition = () => {
            if (buttonRef.current) {
                const rect = buttonRef.current.getBoundingClientRect()
                const tooltipWidth = 256 // w-64 = 16rem = 256px
                const viewportWidth = window.innerWidth

                let left = rect.left + rect.width / 2

                // Basic boundary check to prevent horizontal scroll
                // If tooltip would go off the right edge (minus some padding)
                if (left + tooltipWidth / 2 > viewportWidth - 20) {
                    left = viewportWidth - tooltipWidth / 2 - 20
                }
                // If tooltip would go off the left edge
                if (left - tooltipWidth / 2 < 20) {
                    left = tooltipWidth / 2 + 20
                }

                // Vertical flip logic
                // Default is above. If not enough space (arbitrary 150px safety), flip to below
                const isTop = rect.top > 150

                setPosition({
                    top: isTop ? rect.top : rect.bottom,
                    left: left,
                    placement: isTop ? 'top' : 'bottom' // Add placement info
                })
            }
        }

        updatePosition()
        window.addEventListener('resize', updatePosition)
        window.addEventListener('scroll', updatePosition, true)

        return () => {
            window.removeEventListener('resize', updatePosition)
            window.removeEventListener('scroll', updatePosition, true)
        }
    }, [isOpen])

    const handleMouseEnter = () => {
        if (timerRef.current) clearTimeout(timerRef.current)
        setIsOpen(true)
    }

    const handleMouseLeave = () => {
        timerRef.current = setTimeout(() => {
            setIsOpen(false)
        }, 100)
    }

    const text = contentKey ? t(contentKey) : content

    if (!text) return null

    return (
        <div className="relative inline-flex items-center ml-1 align-middle">
            <button
                ref={buttonRef}
                type="button"
                onClick={() => setIsOpen(!isOpen)}
                onMouseEnter={handleMouseEnter}
                onMouseLeave={handleMouseLeave}
                className={`text-slate-400 hover:text-primary-500 transition-colors focus:outline-none ${className}`}
                aria-label="Help"
            >
                <svg
                    xmlns="http://www.w3.org/2000/svg"
                    viewBox="0 0 20 20"
                    fill="currentColor"
                    className="w-4 h-4"
                >
                    <path
                        fillRule="evenodd"
                        d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zM8.94 6.94a.75.75 0 11-1.061-1.061 3 3 0 112.871 5.026v.345a.75.75 0 01-1.5 0v-.5c0-.72.57-1.172 1.081-1.287A1.5 1.5 0 108.94 6.94zM10 15a1 1 0 100-2 1 1 0 000 2z"
                        clipRule="evenodd"
                    />
                </svg>
            </button>

            {isOpen && position && createPortal(
                <div
                    ref={tooltipRef}
                    className="fixed z-[99999] w-64 p-3 bg-slate-800 text-white text-xs rounded-lg shadow-xl animate-in fade-in zoom-in-95 duration-100"
                    style={{
                        top: position.top,
                        left: position.left,
                        transform: position.placement === 'top'
                            ? 'translate(-50%, -100%) translateY(-8px)'
                            : 'translate(-50%, 0) translateY(8px)',
                        pointerEvents: 'auto'
                    }}
                    onMouseEnter={handleMouseEnter}
                    onMouseLeave={handleMouseLeave}
                    role="tooltip"
                >
                    {/* Arrow */}
                    <div
                        className={`absolute left-1/2 -translate-x-1/2 border-4 border-transparent ${position.placement === 'top'
                                ? 'top-full -mt-[1px] border-t-slate-800'
                                : 'bottom-full -mb-[1px] border-b-slate-800'
                            }`}
                    />

                    <div className="leading-relaxed whitespace-pre-line">
                        {text}
                    </div>
                </div>,
                document.body
            )}
        </div>
    )
}
