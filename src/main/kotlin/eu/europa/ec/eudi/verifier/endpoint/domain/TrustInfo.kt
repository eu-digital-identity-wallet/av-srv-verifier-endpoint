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

/**
 * A single trust/validation check performed on a presented mso_mdoc document.
 *
 * Each constant corresponds to one or more failure reasons of the validation pipeline
 * (see the `DocumentError` variants in the mso adapter) and is reported individually so the
 * frontend can render the full per-check trust report, instead of only the first reason a
 * document would have been rejected under the fail-fast path.
 */
enum class MsoMdocCheck {
    /** The issuer certificate chain is anchored in a trusted list. */
    IssuerChainTrusted,

    /** Validity information (validFrom / validUntil) is present in the MSO. */
    ValidityInfoPresent,

    /** The current time is within the document's validity period. */
    NotExpired,

    /** The issuer key is an EC key, as required for COSE verification. */
    IssuerKeyIsEC,

    /** The issuer signature over the MSO is cryptographically valid. */
    IssuerSignatureValid,

    /** The document type matches the one requested by the verifier. */
    DocumentTypeMatches,

    /** The digests of the issuer-signed items match those listed in the MSO. */
    IssuerSignedItemsValid,

    /** The document has not been revoked according to its status mechanism. */
    NotRevoked,

    /** Device-signed data is present in the document. */
    DeviceSignedPresent,

    /** The device key is authorized to sign the presented data elements. */
    DeviceKeyAuthorized,

    /** The device public key can be parsed and is an EC key. */
    DeviceKeyValid,

    /** The device signature is cryptographically valid. */
    DeviceSignatureValid,
}

/**
 * The outcome of a single [MsoMdocCheck].
 */
sealed interface CheckOutcome {
    /** The check was performed and succeeded. */
    data object Passed : CheckOutcome

    /**
     * The check was not performed — e.g. it was disabled by configuration, or a prerequisite
     * (such as the presence of device-signed data) was absent.
     */
    data class Skipped(
        val reason: String? = null,
    ) : CheckOutcome

    /**
     * The check was performed and failed.
     * [detail] is a human-readable explanation derived from the underlying validation error.
     */
    data class Failed(
        val detail: String,
    ) : CheckOutcome
}

/**
 * The full per-check trust report for a single mso_mdoc document inside a device response.
 */
data class DocumentTrustInfo(
    val index: Int,
    val documentType: String,
    val checks: Map<MsoMdocCheck, CheckOutcome>,
) {
    /** `true` when no performed check failed. */
    val valid: Boolean
        get() = checks.values.none { it is CheckOutcome.Failed }

    /** The checks that failed, keyed by check. */
    val failures: Map<MsoMdocCheck, CheckOutcome.Failed>
        get() =
            buildMap {
                checks.forEach { (check, outcome) ->
                    if (outcome is CheckOutcome.Failed) put(check, outcome)
                }
            }
}

/**
 * The aggregated trust report for an mso_mdoc device response.
 *
 * Unlike the fail-fast validation path, this collects the results of every check on every
 * document, so the verifier can always accept the wallet's submission and surface the complete
 * report to the frontend. The frontend (or a strict client) derives the final acceptance decision
 * from [trusted] or from the individual per-document checks.
 */
data class TrustInfo(
    val documents: List<DocumentTrustInfo>,
) {
    /** The overall verdict: there is at least one document and every document passed every performed check. */
    val trusted: Boolean
        get() = documents.isNotEmpty() && documents.all { it.valid }
}
