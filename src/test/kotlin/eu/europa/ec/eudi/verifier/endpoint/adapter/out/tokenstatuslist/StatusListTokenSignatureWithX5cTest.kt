package eu.europa.ec.eudi.verifier.endpoint.adapter.out.tokenstatuslist

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.statium.GetStatusListToken
import eu.europa.ec.eudi.etsi1196x2.consultation.IsChainTrustedForContextF
import eu.europa.ec.eudi.etsi1196x2.consultation.CertificationChainValidation
import eu.europa.ec.eudi.etsi1196x2.consultation.VerificationContext
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.consultation.Ignored
import io.ktor.client.HttpClient
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test
import java.io.File
import java.net.InetSocketAddress
import com.sun.net.httpserver.HttpServer
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Instant

class StatusListTokenSignatureWithX5cTest {

    @Test
    fun `valid status list JWT signed by x5c key is accepted`() = runTest {
        val now = Instant.parse("2026-08-15T12:00:00Z")
        val uri = "http://127.0.0.1:18081/status"

        val key = loadTestKey()
        val certificate = loadTestCertificate()
        val x5c = Base64.encode(certificate.encoded)

        val jwt =
            createJwt(
                uri = uri,
                key = key,
                x5c = x5c,
                now = now,
            )

        assertTrue(
            SignedJWT.parse(jwt).verify(
                ECDSAVerifier(key.toPublicJWK()),
            ),
            "Control: JWT must have a valid signature",
        )

        val parsedHeader = SignedJWT.parse(jwt).header

        assertNotNull(
            parsedHeader.x509CertChain,
            "JWT must contain x5c",
        )

        assertTrue(
            parsedHeader.x509CertChain!!.isNotEmpty(),
            "x5c must contain at least one certificate",
        )

        val parsedCertificate =
            X509CertUtils.parse(
                parsedHeader.x509CertChain!!.first().decode(),
            )

        assertNotNull(parsedCertificate)

        assertTrue(
            parsedCertificate.publicKey.encoded.contentEquals(
                certificate.publicKey.encoded,
            ),
            "x5c certificate must contain the signing public key",
        )

        val server =
            HttpServer.create(
                InetSocketAddress("127.0.0.1", 18081),
                0,
            )

        server.createContext("/status") { exchange ->
            val body = jwt.toByteArray()

            exchange.responseHeaders.set(
                "Content-Type",
                "application/statuslist+jwt",
            )
            exchange.sendResponseHeaders(
                200,
                body.size.toLong(),
            )

            exchange.responseBody.use { output ->
                output.write(body)
            }
        }

        server.start()

        try {
            HttpClient().use { httpClient ->
                val getStatusListToken =
                    GetStatusListToken.usingJwt(
                        clock =
                            object : Clock {
                                override fun now(): Instant = now
                            },
                        httpClient = httpClient,
                        verifyStatusListTokenSignature =
                            verifyStatusListTokenJwtSignatureWithX5c(IsChainTrustedForContextF.Ignored),
                        allowedClockSkew = kotlin.time.Duration.ZERO,
                    )

                val result =
                    getStatusListToken(
                        uri,
                        null,
                    )

                assertTrue(
                    result.isSuccess,
                    "Valid JWT signed by x5c certificate must be accepted: $result",
                )
            }
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun `corrupted status list JWT is rejected by x5c signature verifier`() = runTest {
        val now = Instant.parse("2026-08-15T12:00:00Z")
        val uri = "http://127.0.0.1:18082/status"

        val key = loadTestKey()
        val certificate = loadTestCertificate()
        val x5c = Base64.encode(certificate.encoded)

        val validJwt =
            createJwt(
                uri = uri,
                key = key,
                x5c = x5c,
                now = now,
            )

        /*
         * Corrupt an actual signature byte.
         *
         * We deliberately mutate the decoded signature rather than
         * changing a Base64URL character, because changing a trailing
         * Base64URL character can alter only unused encoding bits.
         */
        val parts =
            validJwt
                .split(".")
                .toMutableList()

        val signatureBytes =
            Base64URL(parts[2]).decode()

        check(signatureBytes.isNotEmpty()) {
            "JWT signature must not be empty"
        }

        signatureBytes[0] =
            (signatureBytes[0].toInt() xor 0x01).toByte()

        parts[2] =
            Base64URL.encode(signatureBytes).toString()

        val corruptedJwt =
            parts.joinToString(".")

        val verifier =
            ECDSAVerifier(key.toPublicJWK())

        assertTrue(
            SignedJWT.parse(validJwt).verify(verifier),
            "Control: original JWT must have a valid signature",
        )

        assertFalse(
            SignedJWT.parse(corruptedJwt).verify(verifier),
            "Control: corrupted JWT must have an invalid signature",
        )

        val signatureVerifier =
            verifyStatusListTokenJwtSignatureWithX5c(
                IsChainTrustedForContextF.Ignored,
            )

        val signatureResult =
            signatureVerifier(
                corruptedJwt,
                now,
            )

        assertTrue(
            signatureResult.isFailure,
            "X5C verifier must reject a cryptographically invalid JWT: $signatureResult",
        )

        val server =
            HttpServer.create(
                InetSocketAddress("127.0.0.1", 18082),
                0,
            )

        server.createContext("/status") { exchange ->
            val body = corruptedJwt.toByteArray()

            exchange.responseHeaders.set(
                "Content-Type",
                "application/statuslist+jwt",
            )
            exchange.sendResponseHeaders(
                200,
                body.size.toLong(),
            )

            exchange.responseBody.use { output ->
                output.write(body)
            }
        }

        server.start()

        try {
            HttpClient().use { httpClient ->
                val getStatusListToken =
                    GetStatusListToken.usingJwt(
                        clock =
                            object : Clock {
                                override fun now(): Instant = now
                            },
                        httpClient = httpClient,
                        verifyStatusListTokenSignature =
                            verifyStatusListTokenJwtSignatureWithX5c(IsChainTrustedForContextF.Ignored),
                        allowedClockSkew = kotlin.time.Duration.ZERO,
                    )

                val result =
                    getStatusListToken(
                        uri,
                        null,
                    )

                assertTrue(
                    result.isFailure,
                    "GetStatusListToken must reject the corrupted JWT: $result",
                )
            }
        } finally {
            server.stop(0)
        }
    }


    @Test
    fun `valid status list JWT with untrusted x5c chain is rejected`() = runTest {
        val now = Instant.parse("2026-08-15T12:00:00Z")
        val uri = "http://127.0.0.1:18083/status"

        val key = loadTestKey()
        val certificate = loadTestCertificate()
        val x5c = Base64.encode(certificate.encoded)

        val jwt =
            createJwt(
                uri = uri,
                key = key,
                x5c = x5c,
                now = now,
            )

        assertTrue(
            SignedJWT.parse(jwt).verify(ECDSAVerifier(key.toPublicJWK())),
            "Control: JWT must have a valid signature",
        )

        val rejectingTrustValidator =
            IsChainTrustedForContextF<
                arrow.core.NonEmptyList<X509Certificate>,
                VerificationContext,
                TrustAnchor,
            > { _, _ ->
                CertificationChainValidation.NotTrusted(
                    IllegalArgumentException("test trust anchor rejection"),
                )
            }

        val signatureVerifier =
            verifyStatusListTokenJwtSignatureWithX5c(
                rejectingTrustValidator,
            )

        val result =
            signatureVerifier(
                jwt,
                now,
            )

        assertTrue(
            result.isFailure,
            "JWT with an untrusted x5c chain must be rejected: $result",
        )
    }

    private fun createJwt(
        uri: String,
        key: ECKey,
        x5c: Base64,
        now: Instant,
    ): String =
        SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType("statuslist+jwt"))
                .x509CertChain(listOf(x5c))
                .build(),
            JWTClaimsSet.Builder()
                .subject(uri)
                .issueTime(
                    java.util.Date.from(
                        now.toJavaInstant(),
                    ),
                )
                .claim(
                    "status_list",
                    mapOf(
                        "bits" to 1,
                        "lst" to "eJxjYGBgAAAABgAB",
                    ),
                )
                .build(),
        ).apply {
            sign(ECDSASigner(key))
        }.serialize()

    private fun loadTestKey(): ECKey {
        val pem =
            File(
                "src/test/resources/tokenstatuslist/status-list-test-key-pkcs8.pem",
            ).readText()

        val privateKey =
            java.security.KeyFactory
                .getInstance("EC")
                .generatePrivate(
                    java.security.spec.PKCS8EncodedKeySpec(
                        java.util.Base64.getMimeDecoder().decode(
                            pem
                                .lineSequence()
                                .filterNot { it.startsWith("-----") }
                                .joinToString(""),
                        ),
                    ),
                )

        val certificate = loadTestCertificate()

        return ECKey.Builder(
            Curve.P_256,
            certificate.publicKey as java.security.interfaces.ECPublicKey,
        )
            .privateKey(
                privateKey as java.security.interfaces.ECPrivateKey,
            )
            .build()
    }

    private fun loadTestCertificate(): java.security.cert.X509Certificate =
        X509CertUtils.parse(
            File(
                "src/test/resources/tokenstatuslist/status-list-test-cert.der",
            ).readBytes(),
        )

    private fun Instant.toJavaInstant(): java.time.Instant =
        java.time.Instant.ofEpochSecond(
            epochSeconds,
            nanosecondsOfSecond.toLong(),
        )
}
