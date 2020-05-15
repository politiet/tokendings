package io.nais.security.oauth2.token

import com.nimbusds.jose.jwk.RSAKey
import io.kotlintest.matchers.collections.shouldContainInOrder
import io.kotlintest.matchers.collections.shouldHaveSize
import io.kotlintest.matchers.string.shouldContain
import io.kotlintest.shouldBe
import io.kotlintest.shouldNotBe
import io.kotlintest.shouldThrow
import io.mockk.mockk
import io.nais.security.oauth2.mock.DataSource
import io.nais.security.oauth2.mock.withMigratedDb
import io.nais.security.oauth2.utils.generateAESKey
import kotliquery.queryOf
import kotliquery.sessionOf
import kotliquery.using
import org.junit.jupiter.api.Test
import java.text.ParseException
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.temporal.ChronoUnit

internal class RsaKeyStoreTest {


    @Test
    fun `rotation test`(){



        val now = ZonedDateTime.now()
        val oneDayAgo = now.minusDays(1)
        val created = ZonedDateTime.ofInstant(Instant.now().minus(0, ChronoUnit.DAYS).minusSeconds(0), ZoneId.systemDefault())
        println("isBefore?" + created.isBefore(oneDayAgo))
        println("created: $created")
        println("isAfter:" + Instant.now().minus(2, ChronoUnit.DAYS).isAfter(created.toInstant()))
        println("duration:" + Duration.between(created.toInstant(), Instant.now()).toDays())


        val activeRsaKeys = ActiveRsaKeys(listOf())
        val shouldRotate = activeRsaKeys.mostRecentKey?.isOlderThan(1) ?: true
        shouldRotate shouldBe true

        val activeRsaKeys2 = ActiveRsaKeys(
            listOf(
                ActiveRsaKey(
                    ZonedDateTime.now().minusDays(2),
                    mockk()
                )
            )
        )
        val shouldRotate2 = activeRsaKeys2.mostRecentKey?.isOlderThan(1) ?: true
        shouldRotate2 shouldBe true

        val activeRsaKeys3 = ActiveRsaKeys(
            listOf(
                ActiveRsaKey(
                    ZonedDateTime.now().minusDays(1).plusSeconds(1),
                    mockk()
                )
            )
        )
        val shouldRotate3 = activeRsaKeys3.mostRecentKey?.isOlderThan(1) ?: true
        shouldRotate3 shouldBe false
        println("should rotate: $shouldRotate3")


        /*Instant.now().to
        Duration.between(Instant.now(), created.toInstant()).toDays() >= days*/
/*
        withMigratedDb {
            with(tokenIssuerKeyStore()) {
                insertNewKeyPair()
               val created = using(sessionOf(DataSource.instance)) { session ->
                    session.run(
                        queryOf(
                            """SELECT * FROM token_issuer_keys """
                        ).map {
                            it.string("created").apply {
                                println("created: $this")
                            }
                        }.asList
                    )
                }
            }
        }*/
    }

    fun `scaling of pods should work with key rotation and cache strategy`(){

    }

    @Test
    fun `new keypair should be inserted`() {
        withMigratedDb {
            with(tokenIssuerKeyStore()) {
                val rsaKey = insertNewKeyPair()
                rsaKey shouldNotBe null
            }
        }
    }

    @Test
    fun `latestKeyPair should return latest keypair as RSAKey`() {
        withMigratedDb {
            with(tokenIssuerKeyStore()) {
                val first = insertNewKeyPair()
                val second = insertNewKeyPair()
                val jwk = latestKeyPair()
                jwk shouldBe second
            }
        }
    }

    @Test
    fun `latestKeyPairs should return N most recent active keypairs`() {
        withMigratedDb {
            with(tokenIssuerKeyStore()) {
                mostRecentKeys(1) shouldHaveSize 0
                val first = insertNewKeyPair()
                mostRecentKeys(1) shouldHaveSize 1
                val second = insertNewKeyPair()
                mostRecentKeys(3) shouldHaveSize 2
                val third = insertNewKeyPair()
                val lastTwo = mostRecentKeys(2)
                lastTwo.map { it.rsaKey }.toList() shouldContainInOrder listOf(third, second)
            }
        }
    }

    @Test
    fun `findKeyPair should return RSAKey`() {
        withMigratedDb {
            with(tokenIssuerKeyStore()) {
                val keyToFind = insertNewKeyPair()
                val jwk = findKeyPair(keyToFind.keyID)
                jwk shouldBe keyToFind
            }
        }
    }

    @Test
    fun `verify jwk column is encrypted`() {
        withMigratedDb {
            with(tokenIssuerKeyStore()) {
                val keyToFind = insertNewKeyPair()
                val encryptedContent = using(sessionOf(DataSource.instance)) { session ->
                    session.run(
                        queryOf(
                            """SELECT * FROM token_issuer_keys WHERE kid=?""", keyToFind.keyID
                        ).map {
                            it.string("jwk")
                        }.asSingle
                    )
                }
                val exception = shouldThrow<ParseException> {
                    RSAKey.parse(encryptedContent)
                }
                exception.message shouldContain "Invalid JSON"
            }
        }
    }

    private fun tokenIssuerKeyStore() = RsaKeyStore(DataSource.instance, 2048, generateAESKey())
}
