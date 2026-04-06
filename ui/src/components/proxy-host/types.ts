import type { ProxyHost, CreateProxyHostRequest } from '../../types/proxy-host'
import type { CreateCertificateRequest } from '../../types/certificate'
import type { CreateBotFilterRequest, CreateURIBlockRequest, URIBlockRule } from '../../types/security'
import type { CreateGeoRestrictionRequest } from '../../types/access'

export type TabType = 'basic' | 'ssl' | 'security' | 'performance' | 'advanced' | 'protection' | 'upstream'

export interface ProxyHostFormProps {
  host?: ProxyHost | null
  onClose: () => void
}

export interface CertificateState {
  mode: 'select' | 'create'
  data: CreateCertificateRequest
  creating: boolean
  error: string | null
  success: string | null
  progress: string | null
  elapsedTime: number
}

export interface BotFilterState extends CreateBotFilterRequest {
  enabled: boolean
}

export interface GeoDataState extends CreateGeoRestrictionRequest {
  enabled: boolean
}

export interface URIBlockState extends CreateURIBlockRequest {
  enabled: boolean
  rules: URIBlockRule[]
}

export interface FormErrors {
  domain_names?: string
  forward_host?: string
  forward_port?: string
  certificate_id?: string
  [key: string]: string | undefined
}

// Props for tab components
export interface BasicTabProps {
  formData: CreateProxyHostRequest
  setFormData: React.Dispatch<React.SetStateAction<CreateProxyHostRequest>>
  portInput: string
  setPortInput: (value: string) => void
  errors: FormErrors
  setErrors: React.Dispatch<React.SetStateAction<FormErrors>>
}

export interface SSLTabProps {
  formData: CreateProxyHostRequest
  setFormData: React.Dispatch<React.SetStateAction<CreateProxyHostRequest>>
  certState: CertificateState
  setCertMode: (mode: 'select' | 'create') => void
  setNewCertData: React.Dispatch<React.SetStateAction<CreateCertificateRequest>>
  errors: FormErrors
  availableCerts: Array<{
    id: string
    domain_names: string[]
    provider: string
    status: string
  }>
  pendingCerts: Array<{
    id: string
    domain_names: string[]
    provider: string
    status: string
  }>
  dnsProviders: Array<{
    id: string
    name: string
    provider_type: string
  }>
}

export interface SecurityTabProps {
  formData: CreateProxyHostRequest
  setFormData: React.Dispatch<React.SetStateAction<CreateProxyHostRequest>>
  botFilterData: BotFilterState
  setBotFilterData: React.Dispatch<React.SetStateAction<BotFilterState>>
  geoData: GeoDataState
  setGeoData: React.Dispatch<React.SetStateAction<GeoDataState>>
  geoSearchTerm: string
  setGeoSearchTerm: (value: string) => void
  allowedIPsInput: string
  setAllowedIPsInput: (value: string) => void
  blockedCloudProviders: string[]
  setBlockedCloudProviders: (providers: string[]) => void
  uriBlockData: URIBlockState
  setURIBlockData: React.Dispatch<React.SetStateAction<URIBlockState>>
  availableAccessLists: Array<{
    id: string
    name: string
    satisfy_any: boolean
  }>
  geoipStatus: { status: string } | undefined
  countryCodes: Record<string, string> | undefined
}

export interface PerformanceTabProps {
  formData: CreateProxyHostRequest
  setFormData: React.Dispatch<React.SetStateAction<CreateProxyHostRequest>>
}

export interface AdvancedTabProps {
  formData: CreateProxyHostRequest
  setFormData: React.Dispatch<React.SetStateAction<CreateProxyHostRequest>>
}
