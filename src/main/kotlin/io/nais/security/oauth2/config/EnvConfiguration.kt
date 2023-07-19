package io.nais.security.oauth2.config

import com.auth0.jwk.Jwk
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.natpryce.konfig.ConfigurationProperties
import com.natpryce.konfig.EnvironmentVariables
import com.natpryce.konfig.Key
import com.natpryce.konfig.enumType
import com.natpryce.konfig.intType
import com.natpryce.konfig.listType
import com.natpryce.konfig.longType
import com.natpryce.konfig.overriding
import com.natpryce.konfig.stringType
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import io.nais.security.oauth2.authentication.BearerTokenAuth
import io.nais.security.oauth2.config.EnvKey.APPLICATION_PORT
import io.nais.security.oauth2.config.EnvKey.APPLICATION_PROFILE
import io.nais.security.oauth2.config.EnvKey.AUTH_ACCEPTED_AUDIENCE
import io.nais.security.oauth2.config.EnvKey.AUTH_CLIENTS
import io.nais.security.oauth2.config.EnvKey.AUTH_CLIENT_ID
import io.nais.security.oauth2.config.EnvKey.AUTH_CLIENT_JWKS
import io.nais.security.oauth2.config.EnvKey.DB_DATABASE
import io.nais.security.oauth2.config.EnvKey.DB_HOST
import io.nais.security.oauth2.config.EnvKey.DB_PASSWORD
import io.nais.security.oauth2.config.EnvKey.DB_PORT
import io.nais.security.oauth2.config.EnvKey.DB_USERNAME
import io.nais.security.oauth2.config.EnvKey.DEFAULT_TOKEN_EXPIRY_SECONDS
import io.nais.security.oauth2.config.EnvKey.ISSUER_URL
import io.nais.security.oauth2.config.EnvKey.SUBJECT_TOKEN_ISSUERS
import io.nais.security.oauth2.config.EnvKey.TOKEN_EXPIRY_SECONDS
import io.nais.security.oauth2.model.AuthClient
import io.nais.security.oauth2.model.AuthClients
import mu.KotlinLogging
import java.time.Duration
import javax.naming.ConfigurationException

private val log = KotlinLogging.logger {}
val konfig = ConfigurationProperties.systemProperties() overriding
    EnvironmentVariables()

enum class Profile {
    NON_PROD,
    PROD
}

internal object EnvKey {
    const val APPLICATION_PROFILE = "APPLICATION_PROFILE"
    const val DB_HOST = "DB_HOST"
    const val DB_PORT = "DB_PORT"
    const val DB_DATABASE = "DB_DATABASE"
    const val DB_USERNAME = "DB_USERNAME"
    const val DB_PASSWORD = "DB_PASSWORD"
    const val AUTH_ACCEPTED_AUDIENCE = "AUTH_ACCEPTED_AUDIENCE"
    const val AUTH_CLIENT_JWKS = "AUTH_CLIENT_JWKS"
    const val AUTH_CLIENT_ID = "AUTH_CLIENT_ID"
    const val AUTH_CLIENTS = "AUTH_CLIENTS"
    const val APPLICATION_PORT = "APPLICATION_PORT"
    const val TOKEN_EXPIRY_SECONDS = "TOKEN_EXPIRY_SECONDS"
    const val DEFAULT_TOKEN_EXPIRY_SECONDS = 900L
    const val ISSUER_URL = "ISSUER_URL"
    const val SUBJECT_TOKEN_ISSUERS = "SUBJECT_TOKEN_ISSUERS"
}

object Configuration {
    private val issuerUrl = konfig[Key(ISSUER_URL, stringType)]
    private val subjectTokenIssuers = konfig[Key(SUBJECT_TOKEN_ISSUERS, stringType)].split(",").map { it.trim() }
    val instance by lazy {
        val databaseConfig = migrate(databaseConfig())
        val authorizationServerProperties = AuthorizationServerProperties(
            issuerUrl = issuerUrl,
            subjectTokenIssuers = subjectTokenIssuers.toConfiguration(),
            rotatingKeyStore = rotatingKeyStore(
                dataSource = databaseConfig,
                rotationInterval = Duration.ofDays(1)
            ),
            tokenExpiry = konfig.getOrElse(Key(TOKEN_EXPIRY_SECONDS, longType), DEFAULT_TOKEN_EXPIRY_SECONDS)
        )
        val clientRegistry = clientRegistry(databaseConfig)
        val databaseHealthCheck = databaseHealthCheck(databaseConfig)
        val bearerTokenAuthenticationProperties = clientRegistrationAuthProperties()
        AppConfiguration(
            ServerProperties(konfig[Key(APPLICATION_PORT, intType)]),
            clientRegistry,
            authorizationServerProperties,
            bearerTokenAuthenticationProperties,
            databaseHealthCheck
        )
    }
}

fun List<String>.toConfiguration() = this.map { issuerWellKnown ->
    SubjectTokenIssuer(issuerWellKnown)
}

fun configByProfile(): AppConfiguration =
    when (konfig.getOrNull(Key(APPLICATION_PROFILE, enumType<Profile>()))) {
        Profile.NON_PROD -> Configuration.instance
        Profile.PROD -> Configuration.instance
        else -> Configuration.instance
    }

@Suppress("unused")
fun isNonProd() = Profile.PROD != konfig.getOrNull(Key(APPLICATION_PROFILE, enumType<Profile>()))

internal fun databaseConfig(): DatabaseConfig {
    val hostname = konfig[Key(DB_HOST, stringType)]
    val port = konfig[Key(DB_PORT, stringType)]
    val name = konfig[Key(DB_DATABASE, stringType)]
    return DatabaseConfig(
        "jdbc:postgresql://$hostname:$port/$name",
        konfig[Key(DB_USERNAME, stringType)],
        konfig[Key(DB_PASSWORD, stringType)]
    )
}

internal fun clientRegistrationAuthProperties(): ClientRegistrationAuthProperties {
    if (konfig.contains(Key(AUTH_CLIENT_ID, stringType)) && konfig.contains(Key(AUTH_CLIENTS, stringType))) {
        throw ConfigurationException("You cant define both AUTH_CLIENT_ID and AUTH_CLIENTS at the same time.")
    }

    val jwks = konfig[Key(AUTH_CLIENT_JWKS, stringType)].let { JWKSet.parse(it) }.also { jwkSet ->
        log.info("Loaded ${jwkSet.keys.size} keys from JWKS with kids: ${jwkSet.keys.map { it.keyID }}")
    }
    val jacksonMapper = jacksonObjectMapper()
    val authClients = jacksonMapper.readValue(konfig[Key(AUTH_CLIENTS, stringType)], AuthClients::class.java)
    val authProviders = mutableMapOf<String, AuthProvider>()

    if (authClients.clients.isEmpty()) {
        val issuer = konfig[Key(AUTH_CLIENT_ID, stringType)]
        authProviders[issuer] = AuthProvider.fromSelfSigned(issuer, "", jwks)
    }

    authClients.clients.forEach {
        val keysAsJson = jacksonMapper.writeValueAsString(it)
        val authProvider = AuthProvider.fromSelfSigned(it.clientId, it.prefix, JWKSet.parse(keysAsJson))
        authProviders[it.clientId] = authProvider
    }

    return ClientRegistrationAuthProperties(
        authProviders = authProviders,
        acceptedAudience = konfig[Key(AUTH_ACCEPTED_AUDIENCE, listType(stringType, Regex(",")))],
        acceptedRoles = emptyList(),
    )

}
