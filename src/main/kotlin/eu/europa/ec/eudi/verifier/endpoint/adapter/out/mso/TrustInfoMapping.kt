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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso

import eu.europa.ec.eudi.verifier.endpoint.domain.CheckOutcome
import eu.europa.ec.eudi.verifier.endpoint.domain.DocumentTrustInfo
import eu.europa.ec.eudi.verifier.endpoint.domain.MsoMdocCheck

/**
 * The [MsoMdocCheck] that a given [DocumentError] is a failure of. This is the single source of
 * truth for the error-to-check mapping; it lets the collect-all path turn the accumulated
 * `DocumentError`s of a document into a per-check [DocumentTrustInfo] report.
 */
fun DocumentError.check(): MsoMdocCheck =
    when (this) {
        DocumentError.MissingValidityInfo -> MsoMdocCheck.ValidityInfoPresent
        is DocumentError.ExpiredValidityInfo -> MsoMdocCheck.NotExpired
        DocumentError.IssuerKeyIsNotEC -> MsoMdocCheck.IssuerKeyIsEC
        DocumentError.InvalidIssuerSignature -> MsoMdocCheck.IssuerSignatureValid
        is DocumentError.X5CNotTrusted -> MsoMdocCheck.IssuerChainTrusted
        DocumentError.NoMatchingX5CShouldBe -> MsoMdocCheck.IssuerChainTrusted
        DocumentError.DocumentTypeNotMatching -> MsoMdocCheck.DocumentTypeMatches
        DocumentError.InvalidIssuerSignedItems -> MsoMdocCheck.IssuerSignedItemsValid
        DocumentError.DocumentHasBeenRevoked -> MsoMdocCheck.NotRevoked
        is DocumentError.DocumentStatusCheckFailed -> MsoMdocCheck.NotRevoked
        DocumentError.MissingDeviceSigned -> MsoMdocCheck.DeviceSignedPresent
        is DocumentError.DeviceKeyNotAuthorizedToSignItems -> MsoMdocCheck.DeviceKeyAuthorized
        is DocumentError.DevicePublicKeyCannotBeParsed -> MsoMdocCheck.DeviceKeyValid
        is DocumentError.DeviceKeyIsNotEC -> MsoMdocCheck.DeviceKeyValid
        DocumentError.InvalidDeviceSignature -> MsoMdocCheck.DeviceSignatureValid
    }

/**
 * A human-readable explanation of a [DocumentError], used as the [CheckOutcome.Failed.detail] in
 * the trust report.
 */
fun DocumentError.detail(): String =
    when (this) {
        DocumentError.MissingValidityInfo -> {
            "Validity info (validFrom/validUntil) is missing from the MSO"
        }

        is DocumentError.ExpiredValidityInfo -> {
            "Document is outside its validity period ($validFrom .. $validTo)"
        }

        DocumentError.IssuerKeyIsNotEC -> {
            "Issuer key is not an EC key"
        }

        DocumentError.InvalidIssuerSignature -> {
            "Issuer signature over the MSO is invalid"
        }

        is DocumentError.X5CNotTrusted -> {
            "Issuer certificate chain is not trusted${cause?.let { ": $it" } ?: ""}"
        }

        DocumentError.NoMatchingX5CShouldBe -> {
            "No matching X5C trust validator configured for this document type"
        }

        DocumentError.DocumentTypeNotMatching -> {
            "Document type does not match the requested one"
        }

        DocumentError.InvalidIssuerSignedItems -> {
            "Digests of the issuer-signed items do not match the MSO"
        }

        DocumentError.DocumentHasBeenRevoked -> {
            "Document has been revoked"
        }

        is DocumentError.DocumentStatusCheckFailed -> {
            "Revocation status check failed: ${cause.message ?: cause::class.java.simpleName}"
        }

        DocumentError.MissingDeviceSigned -> {
            "Device-signed data is missing from the document"
        }

        is DocumentError.DeviceKeyNotAuthorizedToSignItems -> {
            "Device key is not authorized to sign the presented items: " +
                unauthorized.entries.joinToString { (ns, items) -> "$ns=${items.joinToString()}" }
        }

        is DocumentError.DevicePublicKeyCannotBeParsed -> {
            "Device public key cannot be parsed: ${cause.message ?: cause::class.java.simpleName}"
        }

        is DocumentError.DeviceKeyIsNotEC -> {
            "Device key is not an EC key: ${cause.message ?: cause::class.java.simpleName}"
        }

        DocumentError.InvalidDeviceSignature -> {
            "Device signature is invalid"
        }
    }

/**
 * Builds the per-check [DocumentTrustInfo] report for a single document.
 *
 * @param performedChecks the checks that were actually run for this document (config and document
 *   shape determine which apply); defaults to every [MsoMdocCheck].
 * @param errors the accumulated [DocumentError]s for this document; their [check] marks the
 *   corresponding check as [CheckOutcome.Failed]. Every performed check not present in [errors] is
 *   reported as [CheckOutcome.Passed]; checks outside [performedChecks] are [CheckOutcome.Skipped].
 */
fun documentTrustInfo(
    index: Int,
    documentType: String,
    errors: List<DocumentError>,
    performedChecks: Set<MsoMdocCheck> = MsoMdocCheck.entries.toSet(),
): DocumentTrustInfo {
    val failuresByCheck = errors.groupBy { it.check() }
    val checks =
        MsoMdocCheck.entries.associateWith { check ->
            when {
                check !in performedChecks -> CheckOutcome.Skipped()
                check in failuresByCheck -> CheckOutcome.Failed(failuresByCheck.getValue(check).joinToString("; ") { it.detail() })
                else -> CheckOutcome.Passed
            }
        }
    return DocumentTrustInfo(index, documentType, checks)
}

/** Builds the [DocumentTrustInfo] for an already-validated/failed document from an [InvalidDocument]. */
fun InvalidDocument.toDocumentTrustInfo(performedChecks: Set<MsoMdocCheck> = MsoMdocCheck.entries.toSet()): DocumentTrustInfo =
    documentTrustInfo(index, documentType, errors, performedChecks)
