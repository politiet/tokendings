package io.nais.security.oauth2.token

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import io.nais.security.oauth2.metrics.Metrics
import io.nais.security.oauth2.utils.decrypt
import io.nais.security.oauth2.utils.encrypt
import io.nais.security.oauth2.utils.withTimer
import kotliquery.Row
import kotliquery.queryOf
import kotliquery.sessionOf
import kotliquery.using
import mu.KotlinLogging
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.ZonedDateTime
import java.util.UUID
import javax.crypto.SecretKey
import javax.sql.DataSource

private val log = KotlinLogging.logger { }

internal class RsaKeyStore(
    private val dataSource: DataSource,
    private val keySize: Int,
    private val encryptionKeyAES128: SecretKey
) {
    private val rotationIntervalInDays: Long = 1

    companion object {
        private const val TABLE_NAME = "token_issuer_keys"
        private const val NUMBER_OF_ACTIVE_KEYS: Int = 3
    }

    fun getOrRotateActiveKeys(days: Int): ActiveRsaKeys {
        val activeRsaKeys = ActiveRsaKeys(mostRecentKeys(NUMBER_OF_ACTIVE_KEYS))
        if (activeRsaKeys.shouldRotate(rotationIntervalInDays)) {
            insertNewKeyPair()
            return ActiveRsaKeys(mostRecentKeys(NUMBER_OF_ACTIVE_KEYS))
        }
        return activeRsaKeys
    }

    internal fun mostRecentKeys(limit: Int): List<ActiveRsaKey> =
        withTimer(Metrics.dbTimer.labels("latestKeyPairs")) {
            using(sessionOf(dataSource)) { session ->
                session.run(
                    queryOf(
                        """SELECT kid, jwk, created FROM $TABLE_NAME ORDER BY created DESC LIMIT $limit;"""
                    ).map {
                        ActiveRsaKey(
                            it.zonedDateTime("created"),//it.localDateTime("created")
                            it.decryptRsaKey(encryptionKeyAES128)
                        )
                    }.asList
                )
            }
        }


    fun insertNewKeyPair(): RSAKey {
        val rsaKey = generateRSAKey(keySize)
        val encryptedRsaKey = rsaKey.encrypt(encryptionKeyAES128)
        withTimer(Metrics.dbTimer.labels("insertNewKeyPair")) {
            using(sessionOf(dataSource)) { session ->
                session.run(
                    queryOf(
                        """INSERT INTO $TABLE_NAME(kid, jwk) values (?,?)""".trimMargin(), rsaKey.keyID, encryptedRsaKey
                    ).asUpdate
                )
            }
        }
        return rsaKey
    }

    fun findKeyPair(kid: String) =
        withTimer(Metrics.dbTimer.labels("findKeyPair")) {
            using(sessionOf(dataSource)) { session ->
                session.run(
                    queryOf(
                        """SELECT * FROM $TABLE_NAME WHERE kid=?""", kid
                    ).map {
                        it.decryptRsaKey(encryptionKeyAES128)
                    }.asSingle
                )
            }
        }

    fun latestKeyPair(): RSAKey? =
        withTimer(Metrics.dbTimer.labels("latestKeyPair")) {
            using(sessionOf(dataSource)) { session ->
                session.run(
                    queryOf(
                        """SELECT DISTINCT ON (created) kid, jwk, created FROM $TABLE_NAME ORDER BY created DESC;"""
                    ).map {
                        it.decryptRsaKey(encryptionKeyAES128)
                    }.asSingle
                )
            }
        }

    private fun RSAKey.encrypt(key: SecretKey): String =
        this.toJSONString().encrypt(key)

    private fun Row.decryptRsaKey(key: SecretKey): RSAKey =
        RSAKey.parse(this.string("jwk").decrypt(key))

    private fun generateRSAKey(keySize: Int): RSAKey =
        KeyPairGenerator.getInstance("RSA").apply { initialize(keySize) }.generateKeyPair()
            .let {
                RSAKey.Builder(it.public as RSAPublicKey)
                    .privateKey(it.private as RSAPrivateKey)
                    .keyID(UUID.randomUUID().toString())
                    .keyUse(KeyUse.SIGNATURE)
                    .build()
            }
}


data class ActiveRsaKeys(
    val keys: List<ActiveRsaKey>
) {
    val mostRecentKey: ActiveRsaKey? = keys.maxBy { it.created }
    val jwkSet: JWKSet = JWKSet(keys.map { it.rsaKey }.toList())
    fun shouldRotate(rotationIntervalInDays: Long): Boolean = mostRecentKey?.isOlderThan(rotationIntervalInDays) ?: true
}

data class ActiveRsaKey(
    val created: ZonedDateTime,
    val rsaKey: RSAKey
)

fun ActiveRsaKey.isOlderThan(days: Long) = created.isBefore(ZonedDateTime.now().minusDays(days))
