package io.nais.security.oauth2.model;

import io.kotest.matchers.equals.shouldBeEqual
import org.intellij.lang.annotations.Language
import org.junit.jupiter.api.Test;

internal class SubjectTokenMappingsTest {

    @Test
    fun `deserialize JSON to list of SubjectTokenMapping`() {
        @Language("JSON")
        val json = """
            [
                {
                    "wellKnownUrl": "some-well-known-url",
                    "claimMappings": [
                        { 
                            "claim": "claim1", 
                            "valueMappings": [
                                { "from": "claim1value", "to": "newclaim1value" }, 
                                { "from": "claim1othervalue", "to": "newclaim1othervalue" }
                            ]
                        },
                        { 
                            "claim": "claim2", 
                            "valueMappings": [
                                { "from": "claim2value", "to": "newclaim2value" }
                            ]
                        }
                    ]
                }
            ]
        """.trimIndent()

        val expected = mapOf(
            "some-well-known-url" to listOf(
                SubjectTokenMapping(
                    claim = "claim1",
                    valueMappings = listOf(
                        ClaimValueMapping(from = "claim1value", to = "newclaim1value"),
                        ClaimValueMapping(from = "claim1othervalue", to = "newclaim1othervalue"),
                    )
                ),
                SubjectTokenMapping(
                    claim = "claim2",
                    valueMappings = listOf(
                        ClaimValueMapping(from = "claim2value", to = "newclaim2value"),
                    )
                )
            )
        )

        val deserialized: Map<String, List<SubjectTokenMapping>> = IssuerSubjectTokenMappings.fromJson(json)
        deserialized shouldBeEqual expected
    }
}
