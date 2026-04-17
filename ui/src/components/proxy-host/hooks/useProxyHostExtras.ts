import { useQueryClient } from '@tanstack/react-query'
import { deleteGeoRestriction, getGeoRestriction, setGeoRestriction } from '../../../api/access'
import { updateBotFilter } from '../../../api/security'
import { api } from '../../../api/client'
import type { BotFilterState, GeoDataState } from '../types'

/** Arguments required by {@link ProxyHostExtras.saveExtrasForCreate}. */
interface SaveExtrasCreateArgs {
  hostId: string
  botFilterData: BotFilterState
  geoData: GeoDataState
  blockedCloudProviders: string[]
  cloudProviderChallengeMode: boolean
  cloudProviderAllowSearchBots: boolean
}

/** Arguments required by {@link ProxyHostExtras.saveExtrasForUpdate}. */
interface SaveExtrasUpdateArgs extends SaveExtrasCreateArgs {
  /**
   * The pre-existing geo restriction for this host. We use this to
   * decide whether to DELETE the restriction when the user has cleared
   * all geo settings (vs. a host that never had one).
   */
  existingGeoRestriction: Awaited<ReturnType<typeof getGeoRestriction>> | null | undefined
}

/**
 * Hook that exposes two methods for saving the "extras" (bot filter,
 * geo restriction, cloud provider blocking). Each extra is saved with
 * `skip_reload=true` so the caller can issue a single nginx config
 * regenerate after all extras are applied.
 *
 * Behavior differs between create (only save what's enabled) and update
 * (always save all three, including delete-on-unset for geo).
 */
export function useProxyHostExtras() {
  const queryClient = useQueryClient()

  /**
   * For the CREATE flow: a freshly-created host has no prior settings,
   * so we only need to issue API calls for the extras that are actually
   * set. Errors are logged but do NOT abort the flow — the primary host
   * is already created, losing a bot filter write is recoverable.
   *
   * Runs all applicable calls in parallel.
   *
   * @returns true when at least one extra was saved (so the caller
   *          knows it needs to regenerate the nginx config afterwards).
   */
  async function saveExtrasForCreate({
    hostId,
    botFilterData,
    geoData,
    blockedCloudProviders,
    cloudProviderChallengeMode,
    cloudProviderAllowSearchBots,
  }: SaveExtrasCreateArgs): Promise<boolean> {
    const promises: Promise<unknown>[] = []

    if (
      botFilterData.enabled ||
      botFilterData.custom_blocked_agents ||
      botFilterData.custom_allowed_agents
    ) {
      promises.push(
        updateBotFilter(hostId, botFilterData, true).catch((err) =>
          console.error('Failed to save bot filter:', err),
        ),
      )
    }

    if (
      (geoData.enabled && geoData.countries.length > 0) ||
      (geoData.allowed_ips?.length ?? 0) > 0
    ) {
      promises.push(
        setGeoRestriction(
          hostId,
          {
            mode: geoData.mode,
            countries: geoData.countries,
            allowed_ips: geoData.allowed_ips,
            allow_private_ips: geoData.allow_private_ips,
            allow_search_bots: geoData.allow_search_bots,
            enabled: geoData.enabled && geoData.countries.length > 0,
            challenge_mode: geoData.challenge_mode,
          },
          true,
        ).catch((err) => console.error('Failed to save geo restriction:', err)),
      )
    }

    if (
      blockedCloudProviders.length > 0 ||
      cloudProviderChallengeMode ||
      cloudProviderAllowSearchBots
    ) {
      promises.push(
        api
          .put(`/api/v1/proxy-hosts/${hostId}/blocked-cloud-providers?skip_reload=true`, {
            blocked_providers: blockedCloudProviders,
            challenge_mode: cloudProviderChallengeMode,
            allow_search_bots: cloudProviderAllowSearchBots,
          })
          .catch((err) => console.error('Failed to save blocked cloud providers:', err)),
      )
    }

    if (promises.length === 0) return false
    await Promise.all(promises)
    return true
  }

  /**
   * For the UPDATE flow: always save all three extras in parallel. Geo
   * restriction DELETEs when the user has cleared both country blocking
   * and priority-allow IPs (but only if a record previously existed).
   *
   * Errors per-extra are logged, not thrown — mirrors the original hook
   * which rejected only on nginx regenerate failure (handled by caller).
   */
  async function saveExtrasForUpdate({
    hostId,
    botFilterData,
    geoData,
    blockedCloudProviders,
    cloudProviderChallengeMode,
    cloudProviderAllowSearchBots,
    existingGeoRestriction,
  }: SaveExtrasUpdateArgs): Promise<void> {
    const promises = [
      // Bot filter (skip reload)
      updateBotFilter(hostId, botFilterData, true)
        .then(() => queryClient.invalidateQueries({ queryKey: ['botFilter', hostId] }))
        .catch((err) => console.error('Failed to save bot filter:', err)),

      // Geo restriction (skip reload)
      (async () => {
        try {
          const hasGeoBlocking = geoData.enabled && geoData.countries.length > 0
          const hasPriorityAllowIPs = (geoData.allowed_ips?.length ?? 0) > 0

          if (hasGeoBlocking || hasPriorityAllowIPs) {
            await setGeoRestriction(
              hostId,
              {
                mode: geoData.mode,
                countries: geoData.countries,
                allowed_ips: geoData.allowed_ips,
                allow_private_ips: geoData.allow_private_ips,
                allow_search_bots: geoData.allow_search_bots,
                enabled: hasGeoBlocking,
                challenge_mode: geoData.challenge_mode,
              },
              true,
            )
          } else if (existingGeoRestriction) {
            await deleteGeoRestriction(hostId, true)
          }
          queryClient.invalidateQueries({ queryKey: ['geoRestriction', hostId] })
        } catch (err) {
          console.error('Failed to save geo restriction:', err)
        }
      })(),

      // Blocked cloud providers (skip reload)
      api
        .put(`/api/v1/proxy-hosts/${hostId}/blocked-cloud-providers?skip_reload=true`, {
          blocked_providers: blockedCloudProviders,
          challenge_mode: cloudProviderChallengeMode,
          allow_search_bots: cloudProviderAllowSearchBots,
        })
        .then(() =>
          queryClient.invalidateQueries({ queryKey: ['blockedCloudProviders', hostId] }),
        )
        .catch((err) => console.error('Failed to save blocked cloud providers:', err)),
    ]

    await Promise.all(promises)
  }

  return {
    saveExtrasForCreate,
    saveExtrasForUpdate,
  }
}

/** Public return type, inferred. */
export type ProxyHostExtras = ReturnType<typeof useProxyHostExtras>
