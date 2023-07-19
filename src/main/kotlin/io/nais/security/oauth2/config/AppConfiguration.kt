package io.nais.security.oauth2.config

import com.auth0.jwk.Jwk
import com.auth0.jwk.JwkException
import com.auth0.jwk.JwkProvider
import com.nimbusds.jose.jwk.JWKSet
import com.zaxxer.hikari.HikariDataSource
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.nais.security.oauth2.authentication.BearerTokenAuth
import io.nais.security.oauth2.defaultHttpClient
import io.nais.security.oauth2.health.DatabaseHealthCheck
import io.nais.security.oauth2.health.HealthCheck
import io.nais.security.oauth2.keystore.RotatingKeyStore
import io.nais.security.oauth2.keystore.RotatingKeyStorePostgres
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
) {
    constructor(
        acceptedAudience: List<String>,
        acceptedRoles: List<String> = BearerTokenAuth.ACCEPTED_ROLES_CLAIM_VALUE,
    ) : this(
        authProviders = emptyMap(),
        acceptedAudience = acceptedAudience,
        acceptedRoles = acceptedRoles,
    )
}

class AuthProvider(
    val issuer: String,
    val prefix: String,
    val jwkProvider: JwkProvider,
    val jwkSet: JWKSet
) {
    companion object {
        fun fromSelfSigned(issuer: String, prefix: String, jwkSet: JWKSet): AuthProvider {
            val jwkProvider = JwkProvider { keyId ->
                Jwk.fromValues(jwkSet.getKeyByKeyId(keyId)?.toJSONObject() ?: throw JwkException("JWK not found"))
            }
            return AuthProvider(issuer, prefix, jwkProvider, jwkSet)
        }
    }
}

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
