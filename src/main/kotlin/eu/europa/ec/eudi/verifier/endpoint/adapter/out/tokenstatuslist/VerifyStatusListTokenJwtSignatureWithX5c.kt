package eu.europa.ec.eudi.verifier.endpoint.adapter.out.tokenstatuslist

import arrow.core.NonEmptyList
import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.etsi1196x2.consultation.CertificationChainValidation
import eu.europa.ec.eudi.etsi1196x2.consultation.IsChainTrustedForContextF
import eu.europa.ec.eudi.etsi1196x2.consultation.VerificationContext
import eu.europa.ec.eudi.statium.VerifyStatusListTokenJwtSignature
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

internal fun verifyStatusListTokenJwtSignatureWithX5c(
    isChainTrustedForContext:
        IsChainTrustedForContextF<NonEmptyList<X509Certificate>, VerificationContext, TrustAnchor>,
): VerifyStatusListTokenJwtSignature =
    VerifyStatusListTokenJwtSignature { token, _ ->
        runCatching {
            val jwt = SignedJWT.parse(token)
            val header = jwt.header

            val chain =
                header.x509CertChain
                    ?.map { encoded ->
                        X509CertUtils.parse(encoded.decode())
                            ?: error("Invalid certificate in x5c")
                    }
                    ?.toNonEmptyListOrNull()
                    ?: error("Missing x5c certificate chain")

            val leaf = chain.head

            when (header.algorithm) {
                JWSAlgorithm.ES256,
                JWSAlgorithm.ES384,
                JWSAlgorithm.ES512 -> {
                    check(leaf.publicKey is ECPublicKey) {
                        "JWT algorithm ${header.algorithm} requires an EC public key"
                    }

                    check(jwt.verify(ECDSAVerifier(leaf.publicKey as ECPublicKey))) {
                        "Invalid JWT signature"
                    }
                }

                JWSAlgorithm.RS256,
                JWSAlgorithm.RS384,
                JWSAlgorithm.RS512 -> {
                    check(leaf.publicKey is RSAPublicKey) {
                        "JWT algorithm ${header.algorithm} requires an RSA public key"
                    }

                    check(jwt.verify(RSASSAVerifier(leaf.publicKey as RSAPublicKey))) {
                        "Invalid JWT signature"
                    }
                }

                else ->
                    error(
                        "Unsupported JWT signature algorithm: ${header.algorithm}",
                    )
            }

            when (
                val validation =
                    isChainTrustedForContext(
                        chain,
                        VerificationContext.Custom("StatusListToken"),
                    )
                // suspend function invocation is handled by the generated lambda
            ) {
                is CertificationChainValidation.Trusted -> Unit
                is CertificationChainValidation.NotTrusted ->
                    throw IllegalStateException(
                        "Status List issuer X5C chain is not trusted",
                        validation.cause,
                    )
                null ->
                    error(
                        "Status List issuer X5C chain trust could not be determined",
                    )
            }
        }
    }
