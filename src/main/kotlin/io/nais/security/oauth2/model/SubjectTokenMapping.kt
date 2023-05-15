package io.nais.security.oauth2.model

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue

object IssuerSubjectTokenMappings {
    fun fromJson(json: String): Map<String, List<SubjectTokenMapping>> = jacksonObjectMapper()
        .readValue<List<IssuerSubjectTokenMapping>>(json)
        .associate { mapping -> mapping.wellKnownUrl to mapping.claimMappings }
}

data class IssuerSubjectTokenMapping(
    val wellKnownUrl: String,
    val claimMappings: List<SubjectTokenMapping>
)

data class SubjectTokenMapping(
    val claim: String,
    val valueMappings: List<ClaimValueMapping>,
)

data class ClaimValueMapping(
    val from: String,
    val to: String,
)
