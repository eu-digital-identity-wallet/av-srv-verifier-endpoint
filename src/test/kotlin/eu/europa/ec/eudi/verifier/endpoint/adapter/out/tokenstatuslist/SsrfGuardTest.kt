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

import io.ktor.http.*
import kotlin.test.Test
import kotlin.test.assertFailsWith

/**
 * Tests for [SsrfGuard]. URLs use IP literals so host resolution is deterministic and requires no DNS.
 */
class SsrfGuardTest {
    private val guard = SsrfGuard()

    @Test
    fun `accepts https url that resolves to a public address`() {
        // 93.184.216.34 is a public IP literal; getAllByName returns it as-is (no DNS).
        guard.ensureAllowed(Url("https://93.184.216.34/statuslist"))
    }

    @Test
    fun `rejects http url by default`() {
        assertFailsWith<StatusListUrlNotAllowedException> {
            guard.ensureAllowed(Url("http://93.184.216.34/statuslist"))
        }
    }

    @Test
    fun `accepts http url when explicitly allowed`() {
        val httpGuard = SsrfGuard(SsrfGuardConfig(allowHttp = true))
        httpGuard.ensureAllowed(Url("http://93.184.216.34/statuslist"))
    }

    @Test
    fun `rejects loopback address`() {
        assertFailsWith<StatusListUrlNotAllowedException> {
            guard.ensureAllowed(Url("https://127.0.0.1/statuslist"))
        }
    }

    @Test
    fun `rejects ipv6 loopback address`() {
        assertFailsWith<StatusListUrlNotAllowedException> {
            guard.ensureAllowed(Url("https://[::1]/statuslist"))
        }
    }

    @Test
    fun `rejects cloud metadata link-local address`() {
        assertFailsWith<StatusListUrlNotAllowedException> {
            guard.ensureAllowed(Url("https://169.254.169.254/latest/meta-data/"))
        }
    }

    @Test
    fun `rejects private site-local address`() {
        assertFailsWith<StatusListUrlNotAllowedException> {
            guard.ensureAllowed(Url("https://10.1.2.3/statuslist"))
        }
        assertFailsWith<StatusListUrlNotAllowedException> {
            guard.ensureAllowed(Url("https://192.168.0.1/statuslist"))
        }
    }

    @Test
    fun `rejects ipv6 unique local address`() {
        assertFailsWith<StatusListUrlNotAllowedException> {
            guard.ensureAllowed(Url("https://[fd00::1]/statuslist"))
        }
    }

    @Test
    fun `rejects cgnat address`() {
        assertFailsWith<StatusListUrlNotAllowedException> {
            guard.ensureAllowed(Url("https://100.64.0.1/statuslist"))
        }
    }

    @Test
    fun `enforces host allow-list`() {
        val restricted = SsrfGuard(SsrfGuardConfig(allowedHosts = setOf("status.example.com")))
        assertFailsWith<StatusListUrlNotAllowedException> {
            restricted.ensureAllowed(Url("https://93.184.216.34/statuslist"))
        }
    }
}
