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
package eu.europa.ec.eudi.verifier.endpoint.port.input

import eu.europa.ec.eudi.verifier.endpoint.domain.CheckOutcome
import eu.europa.ec.eudi.verifier.endpoint.domain.DocumentTrustInfo
import eu.europa.ec.eudi.verifier.endpoint.domain.MsoMdocCheck
import eu.europa.ec.eudi.verifier.endpoint.domain.TrustInfo
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TrustInfoToTest {
    @Test
    fun `toTO maps verdict, per-document validity and each check outcome`() {
        val trustInfo =
            TrustInfo(
                documents =
                    listOf(
                        DocumentTrustInfo(
                            index = 0,
                            documentType = "eu.europa.ec.av.1",
                            checks =
                                mapOf(
                                    MsoMdocCheck.IssuerSignatureValid to CheckOutcome.Passed,
                                    MsoMdocCheck.NotRevoked to CheckOutcome.Skipped(),
                                    MsoMdocCheck.IssuerChainTrusted to CheckOutcome.Failed("trust check could not be performed: boom"),
                                ),
                        ),
                    ),
            )

        val to = trustInfo.toTO()

        assertFalse(to.trusted) // a failed check ⇒ not trusted
        assertEquals(1, to.documents.size)

        val document = to.documents.single()
        assertEquals(0, document.index)
        assertEquals("eu.europa.ec.av.1", document.documentType)
        assertFalse(document.valid)

        assertEquals(CheckStatusTO.Passed, document.checks.getValue(MsoMdocCheck.IssuerSignatureValid.name).status)
        assertNull(document.checks.getValue(MsoMdocCheck.IssuerSignatureValid.name).detail)

        assertEquals(CheckStatusTO.Skipped, document.checks.getValue(MsoMdocCheck.NotRevoked.name).status)

        val trust = document.checks.getValue(MsoMdocCheck.IssuerChainTrusted.name)
        assertEquals(CheckStatusTO.Failed, trust.status)
        assertEquals("trust check could not be performed: boom", trust.detail)
    }

    @Test
    fun `toTO of an all-passing single-document report is trusted and serializes with snake_case keys`() {
        val trustInfo =
            TrustInfo(
                documents =
                    listOf(
                        DocumentTrustInfo(
                            index = 0,
                            documentType = "org.iso.18013.5.1.mDL",
                            checks = mapOf(MsoMdocCheck.DocumentTypeMatches to CheckOutcome.Passed),
                        ),
                    ),
            )

        val to = trustInfo.toTO()
        assertTrue(to.trusted)

        val json = Json.encodeToString(WalletResponseTO.serializer(), WalletResponseTO(trustInfo = to))
        assertTrue(json.contains("\"trust_info\""))
        assertTrue(json.contains("\"document_type\""))
        assertTrue(json.contains("\"passed\""))
    }
}
