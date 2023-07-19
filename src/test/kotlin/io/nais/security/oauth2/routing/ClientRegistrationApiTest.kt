package io.nais.security.oauth2.routing

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.oauth2.sdk.OAuth2Error
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.ktor.client.request.delete
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.*
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.plugins.*
import io.ktor.server.testing.testApplication
import io.nais.security.oauth2.authentication.BearerTokenAuth
import io.nais.security.oauth2.config.AuthProvider
import io.nais.security.oauth2.config.ClientRegistrationAuthProperties
import io.nais.security.oauth2.mock.MockClientRegistry
import io.nais.security.oauth2.mock.mockConfig
import io.nais.security.oauth2.mock.withMockOAuth2Server
import io.nais.security.oauth2.model.ClientRegistrationRequest
import io.nais.security.oauth2.model.JsonWebKeys
import io.nais.security.oauth2.model.SoftwareStatement
import io.nais.security.oauth2.model.SoftwareStatementJwt
import io.nais.security.oauth2.token.sign
import io.nais.security.oauth2.tokenExchangeApp
import io.nais.security.oauth2.utils.jwkSet
import io.nais.security.oauth2.utils.shouldBeObject
import io.prometheus.client.CollectorRegistry
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.mock.oauth2.token.DefaultOAuth2TokenCallback
import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import java.time.Instant
import java.util.Date
import kotlin.math.sign

internal class ClientRegistrationApiTest {

    @AfterEach
    fun tearDown() {
        CollectorRegistry.defaultRegistry.clear()
    }

    @Test
    fun `401 on unauthorized requests`() {
        val config = mockConfig(
            null,
            ClientRegistrationAuthProperties(
                acceptedAudience = emptyList(),
            )
        )
        testApplication {
            application { tokenExchangeApp(config, DefaultRouting(config)) }
            client.post("registration/client").status shouldBe HttpStatusCode.Unauthorized
        }
    }

    @Test
    fun `401 on incorrect audience in token`() {
        val signingKeySet = jwkSet()
        val issuer = "jwker"
        val config = mockConfig(
            null,
            ClientRegistrationAuthProperties(
                authProviders = mapOf(Pair(issuer, AuthProvider.fromSelfSigned(issuer, "", signingKeySet))),
                acceptedAudience = listOf("correct_aud"),
                acceptedRoles = emptyList()
            )
        )
        val token = issueValidSelfSignedToken(signingKeySet, audience = "wrong_aud")
        testApplication {
            application { tokenExchangeApp(config, DefaultRouting(config)) }
            client.post("registration/client") {
                header(HttpHeaders.Authorization, "Bearer $token")
            }.status shouldBe HttpStatusCode.Unauthorized

        }
    }

    @Test
    fun `successful client registration call with bearer token and signed software statement`() {
        val signingKeySet = jwkSet()
        val issuer = "jwker"
        val config = mockConfig(
            null,
            ClientRegistrationAuthProperties(
                authProviders = mapOf(Pair(issuer, AuthProvider.fromSelfSigned(issuer, "", signingKeySet))),
                acceptedAudience = listOf("correct_aud"),
                acceptedRoles = emptyList()
            )
        )
        val token = issueValidSelfSignedToken(signingKeySet)

        testApplication {
            application { tokenExchangeApp(config, DefaultRouting(config)) }
            client.post("registration/client") {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                header(HttpHeaders.Authorization, "Bearer $token")
                setBody(
                    ClientRegistrationRequest(
                        clientName = "cluster1:ns1:client1",
                        jwks = JsonWebKeys(jwkSet()),
                        softwareStatementJwt = softwareStatementJwt(
                            SoftwareStatement(
                                appId = "cluster1:ns1:client1",
                                accessPolicyInbound = listOf("cluster1:ns1:client2"),
                                accessPolicyOutbound = emptyList()
                            ),
                            signingKeySet.keys.first() as RSAKey
                        )
                    ).toJson()
                )
            }.status shouldBe HttpStatusCode.Created
            config.clientRegistry.findClient("cluster1:ns1:client1")?.clientId shouldBe "cluster1:ns1:client1"
        }
    }

    @Test
    fun `client registration call with valid token missing required claim roles should fail`() {
        val signingKeySet = jwkSet()
        val issuer = "jwker"
        val config = mockConfig(
            null,
            ClientRegistrationAuthProperties(
                authProviders = mapOf(Pair(issuer, AuthProvider.fromSelfSigned(issuer, "", signingKeySet))),
                acceptedAudience = listOf("correct_aud"),
                acceptedRoles = listOf("correct_role")
            )
        )
        val token = issueValidSelfSignedToken(signingKeySet, claims = mapOf(Pair("roles", listOf("wrong_role"))))

        testApplication {
            application { tokenExchangeApp(config, DefaultRouting(config)) }
            client.post("registration/client") {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                header(HttpHeaders.Authorization, "Bearer $token")
                setBody(
                    ClientRegistrationRequest(
                        clientName = "cluster1:ns1:client1",
                        jwks = JsonWebKeys(jwkSet()),
                        softwareStatementJwt = softwareStatementJwt(
                            SoftwareStatement(
                                appId = "cluster1:ns1:client1",
                                accessPolicyInbound = listOf("cluster1:ns1:client2"),
                                accessPolicyOutbound = emptyList()
                            ),
                            signingKeySet.keys.first() as RSAKey
                        )
                    ).toJson()
                )
            }.status shouldBe HttpStatusCode.Unauthorized
        }
    }

    @Test
    fun `client registration call with valid bearer token and invalid software statement content should fail`() {
        val signingKeySet = jwkSet()
        val config = mockConfig(
            null,
            ClientRegistrationAuthProperties(
                acceptedAudience = listOf("correct_aud"),
                authProviders = mapOf(Pair("test", AuthProvider.fromSelfSigned("test", "", signingKeySet)))
            )
        )
        val token = issueValidSelfSignedToken(signingKeySet, issuer = "test")

        @Language("JSON")
        val invalidSoftwareStatement: String =
            """
                {
                  "appId": "cluster:ns:app1",
                  "accessPolicyInbound": [
                    "cluster:ns:app2"
                  ],
                  "accessPolicyOutbound": null
                }
                """.trimIndent()

        testApplication {
            application { tokenExchangeApp(config, DefaultRouting(config)) }
            val postResponse = client.post("registration/client") {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                header(HttpHeaders.Authorization, "Bearer $token")
                setBody(invalidSoftwareStatement)
            }

            postResponse.status shouldBe HttpStatusCode.BadRequest
            postResponse.bodyAsText() shouldBe "invalid request content"
            config.clientRegistry.findClient("cluster1:ns1:client1") shouldBe null
        }
    }

    @Test
    fun `client registration call with valid bearer token and invalid software statement signature should fail`() {
        val signingKeySet = jwkSet()
        val config = mockConfig(
            null,
            ClientRegistrationAuthProperties(
                acceptedAudience = listOf("correct_aud"),
                authProviders = mapOf(Pair("test", AuthProvider.fromSelfSigned("test", "", signingKeySet)))
            )
        )
        val token = issueValidSelfSignedToken(signingKeySet, issuer = "test")

        val invalidSoftwareStatement: String = ClientRegistrationRequest(
            "cluster1:ns1:client1",
            JsonWebKeys(jwkSet()),
            softwareStatementJwt(
                SoftwareStatement(
                    appId = "cluster1:ns1:client1",
                    accessPolicyInbound = listOf("cluster1:ns1:client2"),
                    accessPolicyOutbound = emptyList()
                ),
                jwkSet().keys.first() as RSAKey
            )
        ).toJson()

        testApplication {
            application { tokenExchangeApp(config, DefaultRouting(config)) }
            client.post("registration/client") {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                header(HttpHeaders.Authorization, "Bearer $token")
                setBody(invalidSoftwareStatement)
            } shouldBeObject OAuth2Error.INVALID_REQUEST
                .setDescription("token verification failed: Signed+JWT+rejected%3A+Another+algorithm+expected%2C+or+no+matching+key%28s%29+found")
            config.clientRegistry.findClient("cluster1:ns1:client1") shouldBe null
        }
    }

    @Test
    fun `client registration call with valid bearer token and empty JWKS should fail`() {
        val signingKeySet = jwkSet()
        val config = mockConfig(
            null,
            ClientRegistrationAuthProperties(
                acceptedAudience = listOf("correct_aud"),
                authProviders = mapOf(Pair("test", AuthProvider.fromSelfSigned("test", "", signingKeySet)))
            )
        )
        val token = issueValidSelfSignedToken(signingKeySet, issuer = "test")
        val invalidSoftwareStatement: String = ClientRegistrationRequest(
            "cluster1:ns1:client1",
            JsonWebKeys(JWKSet(emptyList())),
            softwareStatementJwt(
                SoftwareStatement(
                    appId = "cluster1:ns1:client1",
                    accessPolicyInbound = listOf("cluster1:ns1:client2"),
                    accessPolicyOutbound = emptyList()
                ),
                signingKeySet.keys.first() as RSAKey
            )
        ).toJson()

        testApplication {
            application { tokenExchangeApp(config, DefaultRouting(config)) }
            client.post("registration/client") {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                header(HttpHeaders.Authorization, "Bearer $token")
                setBody(invalidSoftwareStatement)
            } shouldBeObject OAuth2Error.INVALID_REQUEST.setDescription("empty JWKS not allowed")
            config.clientRegistry.findClient("cluster1:ns1:client1") shouldBe null
        }
    }

    @Test
    fun `delete non-existent client should return 204 No Content`() {
        val signingKeySet = jwkSet()
        val issuer = "jwkerino"
        val config = mockConfig(
            null,
            ClientRegistrationAuthProperties(
                authProviders = mapOf(Pair(issuer, AuthProvider.fromSelfSigned(issuer, "", signingKeySet))),
                acceptedAudience = listOf("test"),
                acceptedRoles = emptyList()
            )
        )
        val token = issueValidSelfSignedToken(signingKeySet, issuer, "test", "test")
        testApplication {
            application { tokenExchangeApp(config, DefaultRouting(config)) }
            client.delete("registration/client/yolo") {
                header(HttpHeaders.Authorization, "Bearer $token")
            }.status shouldBe HttpStatusCode.NoContent
            config.clientRegistry.findClient("yolo") shouldBe null
        }
    }


    @Test
    fun `delete existing client should return 204 No Content`() {
        val signingKeySet = jwkSet()
        val config = mockConfig(
            null,
            ClientRegistrationAuthProperties(
                authProviders = mapOf(Pair("test", AuthProvider.fromSelfSigned("test", "", signingKeySet))),
                acceptedAudience = listOf("correct_aud"),
            )
        )
        val client1 = config.clientRegistry.let { it as MockClientRegistry }.register("client1")
        config.clientRegistry.findClient(client1.clientId) shouldBe client1
        val token = issueValidSelfSignedToken(signingKeySet, issuer = "test")
        testApplication {
            application { tokenExchangeApp(config, DefaultRouting(config)) }
            client.delete("registration/client/${client1.clientId}") {
                header(HttpHeaders.Authorization, "Bearer $token")
            }.status shouldBe HttpStatusCode.NoContent
            config.clientRegistry.findClient(client1.clientId) shouldBe null
        }
    }

    // TODO: tester med prefix
    // + jwker i cluster1 kan registrere client for cluster1
    // + jwker i custer2 kan ikke lage client for cluster1
    // + jwker i custer1 kan slette client for cluster1
    // + jwker i cluster1 kan ikke slette client for custer2
    // jwker1 signerer en software statement som jwker2 sender inn - burde ikke bli godtatt

    @Test
    fun `successful jwker in cluster1 can register client for cluster1`() {
        val signingKeySet1 = jwkSet()
        val signingKeySet2 = jwkSet()
        val config = mockConfig(
            null,
            ClientRegistrationAuthProperties(
                authProviders = mapOf(
                    Pair("cluster2", AuthProvider.fromSelfSigned("cluster2", "pref2", signingKeySet2)),
                    Pair("cluster1", AuthProvider.fromSelfSigned("cluster1", "pref1", signingKeySet1)),
                ),
                acceptedAudience = listOf("correct_aud"),
            )
        )
        val token = issueValidSelfSignedToken(signingKeySet1, issuer = "cluster1")
        testApplication {
            application { tokenExchangeApp(config, DefaultRouting(config)) }
            client.post("registration/client") {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                header(HttpHeaders.Authorization, "Bearer $token")
                setBody(
                    ClientRegistrationRequest(
                        clientName = "na",
                        jwks = JsonWebKeys(jwkSet()),
                        softwareStatementJwt = softwareStatementJwt(
                            SoftwareStatement(
                                appId = "pref1:ns1:client1",
                                accessPolicyInbound = listOf("cluster1:ns1:client2"),
                                accessPolicyOutbound = emptyList()
                            ),
                            signingKeySet1.keys.first() as RSAKey
                        )
                    ).toJson()
                )
            }.status shouldBe HttpStatusCode.Created
            config.clientRegistry.findClient("pref1:ns1:client1")?.clientId shouldBe "pref1:ns1:client1"
        }
    }

    @Test
    fun `successful jwker in cluster2 can register client for cluster2`() {
        val signingKeySet1 = jwkSet()
        val signingKeySet2 = jwkSet()
        val config = mockConfig(
            null,
            ClientRegistrationAuthProperties(
                authProviders = mapOf(
                    Pair("cluster2", AuthProvider.fromSelfSigned("cluster2", "pref2", signingKeySet2)),
                    Pair("cluster1", AuthProvider.fromSelfSigned("cluster1", "pref1", signingKeySet1)),
                ),
                acceptedAudience = listOf("correct_aud"),
            )
        )
        val token = issueValidSelfSignedToken(signingKeySet2, issuer = "cluster2")
        testApplication {
            application { tokenExchangeApp(config, DefaultRouting(config)) }
            client.post("registration/client") {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                header(HttpHeaders.Authorization, "Bearer $token")
                setBody(
                    ClientRegistrationRequest(
                        clientName = "na",
                        jwks = JsonWebKeys(jwkSet()),
                        softwareStatementJwt = softwareStatementJwt(
                            SoftwareStatement(
                                appId = "pref2:ns1:client1",
                                accessPolicyInbound = listOf("cluster1:ns1:client2"),
                                accessPolicyOutbound = emptyList()
                            ),
                            signingKeySet2.keys.first() as RSAKey
                        )
                    ).toJson()
                )
            }.status shouldBe HttpStatusCode.Created
            config.clientRegistry.findClient("pref2:ns1:client1")?.clientId shouldBe "pref2:ns1:client1"
        }
    }

    @Test
    fun `jwker in cluster1 can not register client for cluster2`() {
        val signingKeySet1 = jwkSet()
        val signingKeySet2 = jwkSet()
        val config = mockConfig(
            null,
            ClientRegistrationAuthProperties(
                authProviders = mapOf(
                    Pair("cluster1", AuthProvider.fromSelfSigned("cluster1", "pref1", signingKeySet1)),
                    Pair("cluster2", AuthProvider.fromSelfSigned("cluster2", "pref2", signingKeySet2)),
                ),
                acceptedAudience = listOf("correct_aud"),
            )
        )
        val token = issueValidSelfSignedToken(signingKeySet1, issuer = "cluster1")
        testApplication {
            application { tokenExchangeApp(config, DefaultRouting(config)) }
            val postResponse = client.post("registration/client") {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                header(HttpHeaders.Authorization, "Bearer $token")
                setBody(
                    ClientRegistrationRequest(
                        clientName = "na",
                        jwks = JsonWebKeys(jwkSet()),
                        softwareStatementJwt = softwareStatementJwt(
                            SoftwareStatement(
                                appId = "pref2:ns1:client1",
                                accessPolicyInbound = listOf("cluster1:ns1:client2"),
                                accessPolicyOutbound = emptyList()
                            ),
                            signingKeySet1.keys.first() as RSAKey
                        )
                    ).toJson()
                )
            }
            postResponse.status shouldBe HttpStatusCode.BadRequest
            val bodyAsText = postResponse.bodyAsText()
            bodyAsText shouldBe "invalid request content"
            config.clientRegistry.findClient("pref2:ns1:client1")?.clientId shouldBe null
        }
    }

    @Test
    fun `successful jwker in cluster1 can delete client for cluster1`() {
        val signingKeySet1 = jwkSet()
        val signingKeySet2 = jwkSet()
        val config = mockConfig(
            null,
            ClientRegistrationAuthProperties(
                authProviders = mapOf(
                    Pair("cluster1", AuthProvider.fromSelfSigned("cluster1", "pref1", signingKeySet1)),
                    Pair("cluster2", AuthProvider.fromSelfSigned("cluster2", "pref2", signingKeySet2)),
                ),
                acceptedAudience = listOf("correct_aud"),
            )
        )
        val client1 = config.clientRegistry.let { it as MockClientRegistry }.register("pref1:ns1:client1")
        config.clientRegistry.findClient(client1.clientId) shouldBe client1
        val token = issueValidSelfSignedToken(signingKeySet1, issuer = "cluster1")
        testApplication {
            application { tokenExchangeApp(config, DefaultRouting(config)) }
            client.delete("registration/client/${client1.clientId}") {
                header(HttpHeaders.Authorization, "Bearer $token")
            }.status shouldBe HttpStatusCode.NoContent
            config.clientRegistry.findClient(client1.clientId)?.clientId shouldBe null
        }
    }

    @Test
    fun `jwker in cluster1 can not delete client for cluster2`() {
        val signingKeySet1 = jwkSet()
        val signingKeySet2 = jwkSet()
        val config = mockConfig(
            null,
            ClientRegistrationAuthProperties(
                authProviders = mapOf(
                    Pair("cluster1", AuthProvider.fromSelfSigned("cluster1", "pref1", signingKeySet1)),
                    Pair("cluster2", AuthProvider.fromSelfSigned("cluster2", "pref2", signingKeySet2)),
                ),
                acceptedAudience = listOf("correct_aud"),
            )
        )
        val client2 = config.clientRegistry.let { it as MockClientRegistry }.register("pref2:ns1:client1")
        config.clientRegistry.findClient(client2.clientId) shouldBe client2
        val token = issueValidSelfSignedToken(signingKeySet1, issuer = "cluster1")
        testApplication {
            application { tokenExchangeApp(config, DefaultRouting(config)) }
            val deleteResponse = client.delete("registration/client/${client2.clientId}") {
                header(HttpHeaders.Authorization, "Bearer $token")
            }
            deleteResponse.status shouldBe HttpStatusCode.BadRequest
            deleteResponse.bodyAsText() shouldBe "invalid request content"
            config.clientRegistry.findClient(client2.clientId)?.clientId shouldBe client2.clientId
        }
    }

    @Test
    fun `jwker in cluster1 sign software statement that jwker in cluster2 sends in should give BadRequest`() {
        val signingKeySet1 = jwkSet()
        val signingKeySet2 = jwkSet()
        val config = mockConfig(
            null,
            ClientRegistrationAuthProperties(
                authProviders = mapOf(
                    Pair("cluster2", AuthProvider.fromSelfSigned("cluster2", "pref2", signingKeySet2)),
                    Pair("cluster1", AuthProvider.fromSelfSigned("cluster1", "pref1", signingKeySet1)),
                ),
                acceptedAudience = listOf("correct_aud"),
            )
        )
        val token = issueValidSelfSignedToken(signingKeySet2, issuer = "cluster2")
        testApplication {
            application { tokenExchangeApp(config, DefaultRouting(config)) }
            client.post("registration/client") {
                header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                header(HttpHeaders.Authorization, "Bearer $token")
                setBody(
                    ClientRegistrationRequest(
                        clientName = "na",
                        jwks = JsonWebKeys(jwkSet()),
                        softwareStatementJwt = softwareStatementJwt(
                            SoftwareStatement(
                                appId = "pref2:ns1:client1",
                                accessPolicyInbound = listOf("cluster1:ns1:client2"),
                                accessPolicyOutbound = emptyList()
                            ),
                            signingKeySet1.keys.first() as RSAKey
                        )
                    ).toJson()
                )
            }.status shouldBe HttpStatusCode.BadRequest
            config.clientRegistry.findClient("pref2:ns1:client1") shouldBe null
        }
    }

    private fun softwareStatementJwt(softwareStatement: SoftwareStatement, rsaKey: RSAKey): SoftwareStatementJwt =
        JWTClaimsSet.Builder()
            .claim("appId", softwareStatement.appId)
            .claim("accessPolicyInbound", softwareStatement.accessPolicyInbound)
            .claim("accessPolicyOutbound", softwareStatement.accessPolicyOutbound)
            .build()
            .sign(rsaKey)
            .serialize()

    private fun issueValidSelfSignedToken(
        signingKeySet: JWKSet,
        issuer: String = "jwker",
        audience: String = "correct_aud",
        subject: String = "test_sub",
        claims: Map<String, List<String>> = mapOf(Pair("roles", listOf("access_as_application")))
    ): String {
        val now = Instant.now()
        val tokenBuilder = JWTClaimsSet.Builder()
            .issuer(issuer)
            .audience(audience)
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(60)))
            .notBeforeTime(Date.from(now))
            .subject(subject)
        claims.forEach {
            tokenBuilder.claim(it.key, it.value)
        }
        return tokenBuilder.build()
            .sign(signingKeySet.keys.first() as RSAKey)
            .serialize()
    }
}
