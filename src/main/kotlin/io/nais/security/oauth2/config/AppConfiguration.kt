package io.nais.security.oauth2.config

import com.auth0.jwk.GuavaCachedJwkProvider
import com.auth0.jwk.Jwk
import com.auth0.jwk.JwkException
import com.auth0.jwk.JwkProvider
import com.auth0.jwk.JwkProviderBuilder
import com.auth0.jwk.UrlJwkProvider
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.zaxxer.hikari.HikariDataSource
import io.ktor.client.call.body
import io.ktor.client.request.get
import io.nais.security.oauth2.authentication.BearerTokenAuth
import io.nais.security.oauth2.config.JwkCache.BUCKET_SIZE
import io.nais.security.oauth2.config.JwkCache.CACHE_SIZE
import io.nais.security.oauth2.config.JwkCache.EXPIRES_IN
import io.nais.security.oauth2.defaultHttpClient
import io.nais.security.oauth2.health.DatabaseHealthCheck
import io.nais.security.oauth2.health.HealthCheck
import io.nais.security.oauth2.keystore.RotatingKeyStore
import io.nais.security.oauth2.keystore.RotatingKeyStorePostgres
import io.nais.security.oauth2.model.AuthClient
import io.nais.security.oauth2.model.AuthClientKeys
import io.nais.security.oauth2.model.CacheProperties
import io.nais.security.oauth2.model.WellKnown
import io.nais.security.oauth2.registration.ClientRegistry
import io.nais.security.oauth2.registration.ClientRegistryPostgres
import io.nais.security.oauth2.token.TokenIssuer
import kotlinx.coroutines.runBlocking
import mu.KotlinLogging
import java.net.URL
import java.time.Duration
import java.util.concurrent.TimeUnit
import javax.sql.DataSource

private val log = KotlinLogging.logger {}

object JwkCache {
    const val CACHE_SIZE = 10L
    const val EXPIRES_IN = 24L
    const val BUCKET_SIZE = 10L
}

data class AppConfiguration(
    val serverProperties: ServerProperties,
    val clientRegistry: ClientRegistry,
    val authorizationServerProperties: AuthorizationServerProperties,
    val clientRegistrationAuthProperties: ClientRegistrationAuthProperties,
    val databaseHealthCheck: HealthCheck
) {
    val tokenIssuer: TokenIssuer = TokenIssuer(authorizationServerProperties)
}

data class ServerProperties(val port: Int)

data class ClientRegistryProperties(
    val dataSource: DataSource
)
data class ClientRegistrationAuthProperties(
    val authProviders: Map<String, AuthProvider>,
    val acceptedAudience: List<String>,
    val acceptedRoles: List<String> = BearerTokenAuth.ACCEPTED_ROLES_CLAIM_VALUE,
//    val softwareStatementJwks: JWKSet
) {
    constructor(
        identityProviderWellKnownUrl: String,
        acceptedAudience: List<String>,
        acceptedRoles: List<String> = BearerTokenAuth.ACCEPTED_ROLES_CLAIM_VALUE,
        softwareStatementJwks: JWKSet,
    ) : this(
        authProviders = AuthProvider.fromWellKnownToAuthProviderMap(identityProviderWellKnownUrl),
        acceptedAudience = acceptedAudience,
        acceptedRoles = acceptedRoles,
//        softwareStatementJwks = softwareStatementJwks
    )
}

class AuthProvider(
    val issuer: String,
    val jwkProvider: JwkProvider,
    val jwkSet: JWKSet
) {
    companion object {
        fun fromWellKnownToAuthProviderMap(wellKnown: String): Map<String, AuthProvider> {
            val wk = fromWellKnown(wellKnown)
            return mapOf(Pair(wk.issuer, wk))
        }
        fun fromWellKnown(wellKnownUrl: String): AuthProvider {
            val wellKnown: WellKnown = runBlocking {
                log.info("getting OpenID Connect server metadata from well-known url=$wellKnownUrl")
                defaultHttpClient.get(wellKnownUrl).body()
            }
            val jwk = JwkProviderBuilder(URL(wellKnown.jwksUri))
                .cached(CACHE_SIZE, EXPIRES_IN, TimeUnit.HOURS)
                .rateLimited(BUCKET_SIZE, 1, TimeUnit.MINUTES)
                .build()

            val jwkSet = mutableListOf<JWK>()
            val jwk2 = jwk as GuavaCachedJwkProvider
            // kty, kid, n, e
            jwk2.apply {
//                val keys = AuthClientKeys(it.algorithm, it.id, it.publicKey)

                log.info ( "break $this" )
                log.info ( "break $this" )

//                keys.
            }


            return AuthProvider(wellKnown.issuer, jwk, JWKSet())
        }
        fun fromSelfSigned(issuer: String, jwkSet: JWKSet): AuthProvider {
            val jwk = JwkProvider { keyId ->
                Jwk.fromValues(jwkSet.getKeyByKeyId(keyId)?.toJSONObject() ?: throw JwkException("JWK not found"))
            }

            jwk.apply {
                log.info { "$this" }

            }
            return AuthProvider(issuer, jwk, jwkSet)
        }
    }
}

//class Geir: JwkProvider {
//    private var jwkSet: JWKSet
//
//    constructor(jwkSet: JWKSet) {
//        this.jwkSet = jwkSet
//    }
//
//    override fun get(keyId: String?): Jwk {
//        return this.jwkSet.keys.find { it.keyID == keyId }
//    }
//
//}

class AuthorizationServerProperties(
    val issuerUrl: String,
    val subjectTokenIssuers: List<SubjectTokenIssuer>,
    val tokenExpiry: Long = 300,
    val rotatingKeyStore: RotatingKeyStore,
    val clientAssertionMaxExpiry: Long = 120
) {

    fun tokenEndpointUrl() = issuerUrl.path(tokenPath)
    fun clientRegistrationUrl() = issuerUrl.path(registrationPath)

    companion object {
        const val wellKnownPath = "/.well-known/oauth-authorization-server"
        const val authorizationPath = "/authorization"
        const val tokenPath = "/token"
        const val jwksPath = "/jwks"
        const val registrationPath = "/registration/client"
    }
}

class SubjectTokenIssuer(private val wellKnownUrl: String) {
    val wellKnown: WellKnown = runBlocking {
        log.info("getting OAuth2 server metadata from well-known url=$wellKnownUrl")
        defaultHttpClient.get(wellKnownUrl).body()
    }
    val issuer = wellKnown.issuer
    val cacheProperties = CacheProperties(
        lifeSpan = 180,
        refreshTime = 60,
        timeUnit = TimeUnit.MINUTES,
        jwksURL = URL(wellKnown.jwksUri)
    )
}

data class KeyStoreProperties(
    val dataSource: DataSource,
    val rotationInterval: Duration
)

fun String.path(path: String) = "${this.removeSuffix("/")}/${path.removePrefix("/")}"

fun rotatingKeyStore(dataSource: DataSource, rotationInterval: Duration = Duration.ofDays(1)): RotatingKeyStorePostgres =
    RotatingKeyStorePostgres(
        KeyStoreProperties(
            dataSource = dataSource,
            rotationInterval = rotationInterval
        )
    )

internal fun clientRegistry(dataSource: HikariDataSource): ClientRegistryPostgres =
    ClientRegistryPostgres(
        ClientRegistryProperties(
            dataSource
        )
    )

internal fun migrate(databaseConfig: DatabaseConfig) =
    dataSourceFrom(databaseConfig).apply {
        migrate(this)
    }

internal fun databaseHealthCheck(dataSource: HikariDataSource) =
    DatabaseHealthCheck(dataSource)
