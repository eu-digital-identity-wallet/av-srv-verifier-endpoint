package eu.europa.ec.eudi.verifier.endpoint.adapter.out.tokenstatuslist

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.statium.GetStatusListToken
import eu.europa.ec.eudi.statium.VerifyStatusListTokenJwtSignature
import io.ktor.client.HttpClient
import io.ktor.http.ContentType
import io.ktor.http.contentType
import org.junit.jupiter.api.Test
import java.net.InetSocketAddress
import com.sun.net.httpserver.HttpServer
import kotlinx.coroutines.test.runTest
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Instant

class StatusListTokenSignatureBypassTest {

    @Test
    fun `cryptographically invalid status list JWT is accepted by permissive callback`() = runTest {
        val now = Instant.parse("2026-08-15T12:00:00Z")
        val uri = "http://127.0.0.1:18080/status"

        val signingKey =
            ECKeyGenerator(Curve.P_256)
                .generate()

        val validJwt =
            SignedJWT(
                JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(JOSEObjectType("statuslist+jwt"))
                    .build(),
                JWTClaimsSet.Builder()
                    .subject(uri)
                    .issueTime(java.util.Date.from(now.toJavaInstant()))
                    .claim(
                        "status_list",
                        mapOf(
                            "bits" to 1,
                            "lst" to "eJxjYGBgAAAABgAB",
                        ),
                    )
                    .build(),
            ).apply {
                sign(ECDSASigner(signingKey))
            }.serialize()

        val parts = validJwt.split(".").toMutableList()
        val originalSignature = parts[2]

        parts[2] =
            originalSignature.dropLast(1) +
                if (originalSignature.last() == 'A') "B" else "A"

        val corruptedJwt = parts.joinToString(".")

        val cryptographicVerifier =
            ECDSAVerifier(signingKey.toPublicJWK())

        // Cryptographic control: valid JWT really is valid.
        assertTrue(
            SignedJWT.parse(validJwt).verify(cryptographicVerifier),
            "Control: original JWT must have a valid signature",
        )

        // Cryptographic control: modified JWT really is invalid.
        assertFalse(
            SignedJWT.parse(corruptedJwt).verify(cryptographicVerifier),
            "Control: corrupted JWT must have an invalid signature",
        )

        val server =
            HttpServer.create(InetSocketAddress("127.0.0.1", 18080), 0)

        server.createContext("/status") { exchange ->
            val body = corruptedJwt.toByteArray()

            exchange.responseHeaders.set(
                "Content-Type",
                "application/statuslist+jwt",
            )
            exchange.sendResponseHeaders(200, body.size.toLong())

            exchange.responseBody.use { output ->
                output.write(body)
            }
        }

        server.start()

        try {
            HttpClient().use { httpClient ->

                /*
                 * This is the exact callback currently supplied by
                 * StatusListTokenValidator.
                 */
                val permissiveCallback =
                    VerifyStatusListTokenJwtSignature { _, _ ->
                        Result.success(Unit)
                    }

                val getStatusListToken =
                    GetStatusListToken.usingJwt(
                        clock =
                            object : Clock {
                                override fun now(): Instant = now
                            },
                        httpClient = httpClient,
                        verifyStatusListTokenSignature = permissiveCallback,
                        allowedClockSkew = kotlin.time.Duration.ZERO,
                    )

                val result =
                    getStatusListToken(uri, null)

                /*
                 * The JWT has an invalid cryptographic signature, but
                 * Statium accepts it because the consumer-provided
                 * verifier returned Result.success(Unit).
                 */
                assertTrue(
                    result.isSuccess,
                    "The invalid Status List JWT was rejected; the permissive callback was not reproduced",
                )
            }
        } finally {
            server.stop(0)
        }
    }

    private fun Instant.toJavaInstant(): java.time.Instant =
        java.time.Instant.ofEpochSecond(
            epochSeconds,
            nanosecondsOfSecond.toLong(),
        )
}
