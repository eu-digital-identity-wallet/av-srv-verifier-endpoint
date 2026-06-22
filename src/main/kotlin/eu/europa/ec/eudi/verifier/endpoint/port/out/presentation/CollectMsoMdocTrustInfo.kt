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
package eu.europa.ec.eudi.verifier.endpoint.port.out.presentation

import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.domain.TrustInfo
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifiablePresentation

/**
 * Runs the collect-all validation pipeline over a single Verifiable Presentation and returns the
 * per-check [TrustInfo] report, without rejecting it. Used by the always-accept flow.
 *
 * Returns `null` when no report applies (e.g. the format is not mso_mdoc, or the device response
 * cannot be decoded at all).
 */
fun interface CollectMsoMdocTrustInfo {
    suspend fun collect(
        presentation: Presentation.RequestObjectRetrieved,
        verifiablePresentation: VerifiablePresentation,
    ): TrustInfo?

    companion object {
        val NoOp: CollectMsoMdocTrustInfo = CollectMsoMdocTrustInfo { _, _ -> null }
    }
}
