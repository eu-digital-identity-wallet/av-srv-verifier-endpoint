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

import arrow.core.raise.either
import eu.europa.ec.eudi.verifier.endpoint.TestContext
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.VerifierApiClient
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertIs

/**
 * SEC-06: a missing (null) `response_code` must not act as a wildcard match. For the same-device
 * (redirect) flow a `response_code` is issued and MUST be supplied and match; the cross-device
 * (poll) flow has no `response_code` and remains gated by the transactionId alone.
 */
internal class GetWalletResponseSec06Test {
    private val clock = TestContext.testClock

    private fun submitted(responseCode: ResponseCode?): Presentation.Submitted {
        val at = clock.now()
        val query = VerifierApiClient.loadInitTransactionTO("00-dcql.json").dcqlQuery!!
        val requested =
            Presentation.Requested(
                id = TransactionId("SampleTxId"),
                initiatedAt = at,
                query = query,
                transactionData = null,
                requestId = RequestId("SampleRequestId"),
                requestUriMethod = RequestUriMethod.Get,
                nonce = Nonce("nonce-1"),
                responseMode = ResponseMode.DirectPost,
                getWalletResponseMethod =
                    if (responseCode == null) {
                        GetWalletResponseMethod.Poll
                    } else {
                        GetWalletResponseMethod.Redirect("https://client.example.org/cb#response_code=#CODE#")
                    },
                issuerChain = null,
                profile = Profile.OpenId4VP,
            )
        val retrieved = Presentation.RequestObjectRetrieved.requestObjectRetrieved(requested, at)
        return either {
            Presentation.Submitted.submitted(retrieved, at, WalletResponse.Error("access_denied", null), responseCode)
        }.getOrNull()!!
    }

    private fun sut(presentation: Presentation.Submitted): GetWalletResponse =
        GetWalletResponseLive(
            clock = clock,
            loadPresentationById = { presentation },
            publishPresentationEvent = { },
        )

    @Test
    fun `same-device presentation without response_code is rejected`() =
        runTest {
            val presentation = submitted(ResponseCode("the-code"))
            val result = sut(presentation)(presentation.id, null)
            assertIs<QueryResponse.InvalidState>(result)
        }

    @Test
    fun `same-device presentation with wrong response_code is rejected`() =
        runTest {
            val presentation = submitted(ResponseCode("the-code"))
            val result = sut(presentation)(presentation.id, ResponseCode("wrong"))
            assertIs<QueryResponse.InvalidState>(result)
        }

    @Test
    fun `same-device presentation with correct response_code is returned`() =
        runTest {
            val presentation = submitted(ResponseCode("the-code"))
            val result = sut(presentation)(presentation.id, ResponseCode("the-code"))
            assertIs<QueryResponse.Found<WalletResponseTO>>(result)
        }

    @Test
    fun `poll presentation without response_code is returned`() =
        runTest {
            val presentation = submitted(null)
            val result = sut(presentation)(presentation.id, null)
            assertIs<QueryResponse.Found<WalletResponseTO>>(result)
        }
}
