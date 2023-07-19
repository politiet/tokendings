package io.nais.security.oauth2.routing

import com.nimbusds.oauth2.sdk.OAuth2Error
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.plugins.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nais.security.oauth2.authentication.BearerTokenAuth
import io.nais.security.oauth2.config.AppConfiguration
import io.nais.security.oauth2.model.AccessPolicy
import io.nais.security.oauth2.model.ClientRegistration
import io.nais.security.oauth2.model.ClientRegistrationRequest
import io.nais.security.oauth2.model.GrantType
import io.nais.security.oauth2.model.OAuth2Client
import io.nais.security.oauth2.model.OAuth2Exception
import io.nais.security.oauth2.model.verifySoftwareStatement

internal fun Route.clientRegistrationApi(config: AppConfiguration) {
    authenticate(BearerTokenAuth.CLIENT_REGISTRATION_AUTH) {
        route("/registration/client") {
            post {
                val request: ClientRegistrationRequest = call.receive(ClientRegistrationRequest::class).validate()

                // We know a JWTPrincipal and the AuthProvider for its issuer exists since we passed ktor's authenticate
                val issuer = call.principal<JWTPrincipal>()!!.issuer
                val authProvider = config.clientRegistrationAuthProperties.authProviders[issuer]!!

                val softwareStatement = request.verifySoftwareStatement(authProvider)

                val grantTypes: List<String> = when {
                    request.grantTypes.isEmpty() -> listOf(GrantType.TOKEN_EXCHANGE_GRANT)
                    else -> request.grantTypes
                }
                val clientToRegister = OAuth2Client(
                    softwareStatement.appId,
                    request.jwks,
                    AccessPolicy(softwareStatement.accessPolicyInbound),
                    AccessPolicy(softwareStatement.accessPolicyOutbound),
                    request.scopes,
                    grantTypes
                )
                config.clientRegistry.registerClient(clientToRegister)
                call.respond(
                    HttpStatusCode.Created,
                    ClientRegistration(
                        clientToRegister.clientId,
                        clientToRegister.jwks,
                        request.softwareStatementJwt,
                        clientToRegister.allowedGrantTypes,
                        "private_key_jwt"
                    )
                )
            }
            delete("/{clientId}") {
                // We know a JWTPrincipal and the AuthProvider for its issuer exists since we passed ktor's authenticate
                val issuer = call.principal<JWTPrincipal>()!!.issuer
                val authProvider = config.clientRegistrationAuthProperties.authProviders[issuer]!!

                call.parameters["clientId"]?.let { clientId ->
                    if (!clientId.startsWith(authProvider.prefix)) {
                        throw BadRequestException(message = "can't register app, wrong prefix")
                    }
                    config.clientRegistry.deleteClient(clientId)
                    call.respond(HttpStatusCode.NoContent)
                }
            }
            get {
                call.respond(config.clientRegistry.findAll())
            }
            get("/{clientId}") {
                val client: OAuth2Client? = call.parameters["clientId"]
                    ?.let { config.clientRegistry.findClient(it) }
                when (client) {
                    null -> call.respond(HttpStatusCode.NotFound, "client not found")
                    else -> call.respond(client)
                }
            }
        }
    }
}

private fun ClientRegistrationRequest.validate(): ClientRegistrationRequest {
    require(this.jwks.keys.isNotEmpty()) {
        throw OAuth2Exception(OAuth2Error.INVALID_REQUEST.setDescription("empty JWKS not allowed"))
    }
    return this
}
