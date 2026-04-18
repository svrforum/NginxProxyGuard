# Changelog

## v2.13.0 (2026-04-18)

### Breaking changes

- **TailwindCSS v4**: migrated from PostCSS-based v3 to the Vite-plugin-based v4. Custom `primary` color scale moved to a CSS `@theme` block; `darkMode: 'class'` preserved via `@custom-variant`. Self-maintained forks with custom Tailwind plugins need to consult the [Tailwind v4 upgrade guide](https://tailwindcss.com/docs/upgrade-guide).
- **React 19**: concurrent-mode changes (effects double-invoke in development mode under Strict Mode). `useRef` without initial arg is now a type error. Global `JSX` namespace removed — use `React.JSX`. Most consumers are unaffected at runtime; this primarily affects maintainers writing new components.
- **i18next 26 / react-i18next 17**: init option compatibility verified. No breaking changes observed in our usage.
- **Valkey 9**: in-place upgrade is safe for this project since Valkey is used only as a cache (`pkg/cache/redis.go`). RDB/AOF volume format is backward compatible with Valkey 8. No migration step required.

### Upgrades

- React 18.3 → 19.2
- TailwindCSS 3.4 → 4.2
- Vite 6 → 7 + @vitejs/plugin-react 4 → 5
- ESLint 9 → 10 + typescript-eslint + react plugins
- i18next 25 → 26, react-i18next 16 → 17
- Valkey 8 → 9

## v2.12.0 (2026-04-18)

### Upgrades (low-risk bundle)

- Go toolchain 1.22 → 1.25 (Docker builder: `golang:1.25-alpine`)
- Echo v4.12 → v4.15
- Nginx 1.28 → 1.30 (stable line)
- OWASP CRS 4.21 → 4.25
- TypeScript 5.6 → 5.9
- Vite 6.0 → 6.x latest patch
- @tanstack/react-query 5.60 → 5.99
- react-router-dom 7.9 → 7.14
- recharts 3.5 → 3.8 (minor tooltip formatter adjustments for new `ValueType` widening)
- i18next 25.7 → 25.x latest patch
- Patch-level sweep of remaining Go and npm dependencies
- Node 24 LTS for UI builder (from Node 22)
