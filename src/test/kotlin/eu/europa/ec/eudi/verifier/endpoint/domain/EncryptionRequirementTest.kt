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
package eu.europa.ec.eudi.verifier.endpoint.domain

import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals

/**
 * SEC-31: the supported ECDH-ES key-wrap algorithms must be A128KW, A192KW and A256KW (plus plain
 * ECDH-ES) with no duplicates. A192KW was previously duplicated as A128KW, which both dropped A192KW
 * support and left it out of the preference map.
 */
internal class EncryptionRequirementTest {
    private val expectedEcdhEs =
        setOf(
            JWEAlgorithm.ECDH_ES,
            JWEAlgorithm.ECDH_ES_A128KW,
            JWEAlgorithm.ECDH_ES_A192KW,
            JWEAlgorithm.ECDH_ES_A256KW,
        )

    @Test
    fun `EC key advertises all ECDH-ES key-wrap algorithms without duplicates`() {
        val ecKey = ECKeyGenerator(Curve.P_256).keyUse(KeyUse.ENCRYPTION).generate().toPublicJWK()
        val algorithms = ecKey.supportedEncryptionAlgorithms
        assertEquals(4, algorithms.size)
        assertEquals(4, algorithms.toSet().size, "algorithms must be distinct")
        assertEquals(expectedEcdhEs, algorithms.toSet())
    }

    @Test
    fun `OKP key advertises all ECDH-ES key-wrap algorithms without duplicates`() {
        val okp: OctetKeyPair = OctetKeyPairGenerator(Curve.X25519).keyUse(KeyUse.ENCRYPTION).generate().toPublicJWK()
        val algorithms = okp.supportedEncryptionAlgorithms
        assertEquals(4, algorithms.size)
        assertEquals(4, algorithms.toSet().size, "algorithms must be distinct")
        assertEquals(expectedEcdhEs, algorithms.toSet())
    }

    @Test
    fun `preference map includes A192KW`() {
        assertContains(encryptionAlgorithmPreferenceMap.keys, JWEAlgorithm.ECDH_ES_A192KW)
    }
}
