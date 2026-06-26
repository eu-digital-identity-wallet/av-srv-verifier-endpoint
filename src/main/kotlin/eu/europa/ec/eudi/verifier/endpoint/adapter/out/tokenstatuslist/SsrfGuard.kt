/*
 * Copyright (c) 2023-2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.tokenstatuslist

import io.ktor.client.plugins.api.*
import io.ktor.http.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.slf4j.LoggerFactory
import java.net.InetAddress
import kotlin.time.Duration

private val log = LoggerFactory.getLogger("eu.europa.ec.eudi.verifier.endpoint.adapter.out.tokenstatuslist.SsrfGuard")

/**
 * Raised when a Status List URI presented inside a wallet credential is not allowed to be fetched,
 * because it violates the configured SSRF protection (wrong scheme, host not allow-listed, or it
 * resolves to a private/loopback/link-local/metadata address).
 */
class StatusListUrlNotAllowedException(
    message: String,
) : Exception(message)

/**
 * Configuration of the [SsrfGuard].
 *
 * @param allowHttp when `true`, plain `http` URLs are accepted in addition to `https`. Should only be
 *   enabled for local development/testing.
 * @param allowedHosts when non-empty, only these hosts (case-insensitive, exact match) are accepted.
 *   When empty, any host is accepted as long as it does not resolve to a blocked address.
 */
data class SsrfGuardConfig(
    val allowHttp: Boolean = false,
    val allowedHosts: Set<String> = emptySet(),
)

/**
 * Validates that an outgoing URL — derived from a wallet-presented credential's `status_list.uri` —
 * is safe to fetch, mitigating Server-Side Request Forgery (SSRF):
 *  - only `https` (or `http` when explicitly allowed) is accepted,
 *  - an optional host allow-list is enforced,
 *  - the host is resolved and rejected when it maps to any private, loopback, link-local (incl. the
 *    cloud metadata address `169.254.169.254`), site-local, unique-local, CGNAT or multicast range.
 *
 * Note: a residual DNS-rebinding window exists between this check and the actual connection. It is
 * mitigated by also disabling HTTP redirects on the status-list HTTP client.
 */
class SsrfGuard(
    private val config: SsrfGuardConfig = SsrfGuardConfig(),
) {
    fun ensureAllowed(url: Url) {
        val scheme = url.protocol.name.lowercase()
        val schemeAllowed = scheme == "https" || (config.allowHttp && scheme == "http")
        if (!schemeAllowed) {
            throw StatusListUrlNotAllowedException("Only https URLs are allowed for status list fetching, got scheme '$scheme'")
        }

        val host = url.host.lowercase()
        if (config.allowedHosts.isNotEmpty() && host !in config.allowedHosts) {
            throw StatusListUrlNotAllowedException("Status list host '$host' is not in the configured allow-list")
        }

        val addresses =
            try {
                InetAddress.getAllByName(url.host)
            } catch (e: Exception) {
                throw StatusListUrlNotAllowedException("Could not resolve status list host '${url.host}': ${e.message}")
            }

        addresses.forEach { address ->
            if (address.isDisallowed()) {
                throw StatusListUrlNotAllowedException(
                    "Status list host '${url.host}' resolves to a disallowed address '${address.hostAddress}'",
                )
            }
        }
    }
}

private fun InetAddress.isDisallowed(): Boolean {
    if (isAnyLocalAddress || isLoopbackAddress || isLinkLocalAddress || isSiteLocalAddress || isMulticastAddress) {
        return true
    }
    val bytes = address
    // IPv6 unique local addresses fc00::/7
    if (bytes.size == 16 && (bytes[0].toInt() and 0xFE) == 0xFC) {
        return true
    }
    // IPv4 carrier-grade NAT 100.64.0.0/10
    if (bytes.size == 4) {
        val b0 = bytes[0].toInt() and 0xFF
        val b1 = bytes[1].toInt() and 0xFF
        if (b0 == 100 && b1 in 64..127) {
            return true
        }
    }
    return false
}

/**
 * Bundles the SSRF protection settings applied to the dedicated status-list HTTP client.
 */
data class StatusListSsrfProtection(
    val guard: SsrfGuard,
    val connectTimeout: Duration,
    val requestTimeout: Duration,
    val socketTimeout: Duration,
    val maxResponseBytes: Long,
)

class SsrfGuardPluginConfig {
    lateinit var guard: SsrfGuard
    var maxResponseBytes: Long = Long.MAX_VALUE
}

/**
 * Ktor client plugin that enforces [SsrfGuard] on every outgoing request and rejects responses whose
 * declared `Content-Length` exceeds [SsrfGuardPluginConfig.maxResponseBytes].
 */
val SsrfGuardPlugin =
    createClientPlugin("StatusListSsrfGuard", ::SsrfGuardPluginConfig) {
        val guard = pluginConfig.guard
        val maxResponseBytes = pluginConfig.maxResponseBytes

        onRequest { request, _ ->
            val url = request.url.build()
            // Surfaced so operators can discover which hosts to put on the allow-list by replaying a
            // real wallet flow and grepping for this line.
            log.info("Status list fetch requested: host='{}' port={} scheme='{}'", url.host, url.port, url.protocol.name)
            log.debug("Status list fetch full url: {}", url)
            // DNS resolution is blocking; keep it off the calling (reactor) thread.
            withContext(Dispatchers.IO) {
                try {
                    guard.ensureAllowed(url)
                } catch (e: StatusListUrlNotAllowedException) {
                    log.warn("Status list fetch blocked for host='{}': {}", url.host, e.message)
                    throw e
                }
            }
        }

        onResponse { response ->
            val contentLength = response.contentLength()
            if (contentLength != null && contentLength > maxResponseBytes) {
                log.warn("Rejecting status list response of {} bytes (max {})", contentLength, maxResponseBytes)
                throw StatusListUrlNotAllowedException(
                    "Status list response too large: $contentLength bytes (max $maxResponseBytes)",
                )
            }
        }
    }
