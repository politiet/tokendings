package io.nais.security.oauth2

import com.fasterxml.jackson.databind.SerializationFeature
import io.ktor.application.install
import io.ktor.features.CallId
import io.ktor.features.CallLogging
import io.ktor.features.ContentNegotiation
import io.ktor.features.DoubleReceive
import io.ktor.features.ForwardedHeaderSupport
import io.ktor.features.callIdMdc
import io.ktor.jackson.jackson
import io.ktor.server.engine.applicationEngineEnvironment
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.util.KtorExperimentalAPI
import io.nais.security.oauth2.config.Configuration
import mu.KotlinLogging
import org.slf4j.LoggerFactory
import org.slf4j.event.Level
import java.util.UUID

private val secureLog = LoggerFactory.getLogger("securelog")
private val log = KotlinLogging.logger { }

@KtorExperimentalAPI
fun main() {
    val config = Configuration()
    val app = setupApp(config)
    app.start(wait = true)
}

@KtorExperimentalAPI
private fun setupApp(config: Configuration) =
    embeddedServer(Netty, applicationEngineEnvironment {
        connector {
            port = config.application.port
        }
        module {
            install(CallId) {
                generate {
                    UUID.randomUUID().toString()
                }
            }
            install(CallLogging) {
                logger = log
                level = Level.INFO
                callIdMdc("callId")
            }
            install(ContentNegotiation) {
                jackson {
                    enable(SerializationFeature.INDENT_OUTPUT)
                }
            }
            install(DoubleReceive)
            install(ForwardedHeaderSupport)

            requestResponseTracing(log)
            probesAndMetrics()
            tokenExchangeApi(config)
        }
    })
