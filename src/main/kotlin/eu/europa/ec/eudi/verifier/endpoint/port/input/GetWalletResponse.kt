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

import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.input.QueryResponse.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationById
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

/**
 * Represent the [WalletResponse] as returned by the wallet
 */
@Serializable
@SerialName("wallet_response")
data class WalletResponseTO(
    @SerialName(OpenId4VPSpec.VP_TOKEN) val vpToken: JsonObject? = null,
    @SerialName(RFC6749.ERROR) val error: String? = null,
    @SerialName(RFC6749.ERROR_DESCRIPTION) val errorDescription: String? = null,
    @SerialName("trust_info") val trustInfo: TrustInfoTO? = null,
)

/**
 * The per-check trust report attached to an accepted wallet response, exposed to the frontend.
 * Present only when the verifier runs in always-accept mode.
 */
@Serializable
data class TrustInfoTO(
    val trusted: Boolean,
    val documents: List<DocumentTrustInfoTO>,
)

@Serializable
data class DocumentTrustInfoTO(
    val index: Int,
    @SerialName("document_type") val documentType: String,
    val valid: Boolean,
    val checks: Map<String, CheckOutcomeTO>,
)

@Serializable
data class CheckOutcomeTO(
    val status: CheckStatusTO,
    val detail: String? = null,
)

@Serializable
enum class CheckStatusTO {
    @SerialName("passed")
    Passed,

    @SerialName("skipped")
    Skipped,

    @SerialName("failed")
    Failed,
}

internal fun TrustInfo.toTO(): TrustInfoTO =
    TrustInfoTO(
        trusted = trusted,
        documents =
            documents.map { document ->
                DocumentTrustInfoTO(
                    index = document.index,
                    documentType = document.documentType,
                    valid = document.valid,
                    checks = document.checks.entries.associate { (check, outcome) -> check.name to outcome.toTO() },
                )
            },
    )

private fun CheckOutcome.toTO(): CheckOutcomeTO =
    when (this) {
        CheckOutcome.Passed -> CheckOutcomeTO(CheckStatusTO.Passed)
        is CheckOutcome.Skipped -> CheckOutcomeTO(CheckStatusTO.Skipped, reason)
        is CheckOutcome.Failed -> CheckOutcomeTO(CheckStatusTO.Failed, detail)
    }

internal fun WalletResponse.toTO(): WalletResponseTO {
    fun VerifiablePresentation.toJsonElement(): JsonElement =
        when (this) {
            is VerifiablePresentation.Str -> JsonPrimitive(value)
            is VerifiablePresentation.Json -> value
        }

    fun VerifiablePresentations.toJsonObject(): JsonObject =
        buildJsonObject {
            value.forEach { (queryId, verifiablePresentations) ->
                putJsonArray(queryId.value) {
                    verifiablePresentations.forEach {
                        add(it.toJsonElement())
                    }
                }
            }
        }

    return when (this) {
        is WalletResponse.VpToken -> {
            WalletResponseTO(
                vpToken = verifiablePresentations.toJsonObject(),
            )
        }

        is WalletResponse.Error -> {
            WalletResponseTO(
                error = value,
                errorDescription = description,
            )
        }
    }
}

/**
 * Given a [TransactionId] and a [Nonce] returns the [WalletResponse]
 */
fun interface GetWalletResponse {
    suspend operator fun invoke(
        transactionId: TransactionId,
        responseCode: ResponseCode?,
    ): QueryResponse<WalletResponseTO>
}

class GetWalletResponseLive(
    private val clock: Clock,
    private val loadPresentationById: LoadPresentationById,
    private val publishPresentationEvent: PublishPresentationEvent,
) : GetWalletResponse {
    override suspend fun invoke(
        transactionId: TransactionId,
        responseCode: ResponseCode?,
    ): QueryResponse<WalletResponseTO> =
        when (val presentation = loadPresentationById(transactionId)) {
            null -> {
                NotFound
            }

            is Presentation.Submitted -> {
                when (responseCode) {
                    null,
                    presentation.responseCode,
                    -> found(presentation)

                    else -> responseCodeMismatch(presentation, responseCode)
                }
            }

            else -> {
                invalidState(presentation)
            }
        }

    private suspend fun found(presentation: Presentation.Submitted): Found<WalletResponseTO> {
        val walletResponse = presentation.walletResponse.toTO().copy(trustInfo = presentation.trustInfo?.toTO())
        logVerifierGotWalletResponse(presentation, walletResponse)
        return Found(walletResponse)
    }

    private suspend fun responseCodeMismatch(
        presentation: Presentation.Submitted,
        responseCode: ResponseCode?,
    ): InvalidState {
        fun ResponseCode?.txt() = this?.let { value } ?: "N/A"
        val cause =
            "Invalid response_code. " +
                "Expected: ${presentation.responseCode.txt()}, " +
                "Provided ${responseCode.txt()}"
        logVerifierFailedToGetWalletResponse(presentation, cause)
        return InvalidState
    }

    private suspend fun invalidState(presentation: Presentation): InvalidState {
        val cause = "Presentation should be in Submitted state but is in ${presentation.javaClass.name}"
        logVerifierFailedToGetWalletResponse(presentation, cause)
        return InvalidState
    }

    private suspend fun logVerifierGotWalletResponse(
        presentation: Presentation.Submitted,
        walletResponse: WalletResponseTO,
    ) {
        val event = PresentationEvent.VerifierGotWalletResponse(presentation.id, clock.now(), walletResponse)
        publishPresentationEvent(event)
    }

    private suspend fun logVerifierFailedToGetWalletResponse(
        presentation: Presentation,
        cause: String,
    ) {
        val event = PresentationEvent.VerifierFailedToGetWalletResponse(presentation.id, clock.now(), cause)
        publishPresentationEvent(event)
    }
}
