/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.walletprovider.domain.challenge

import at.asitplus.signum.indispensable.josef.JwsSigned
import eu.europa.ec.eudi.walletprovider.domain.Base64UrlSafeByteArray
import eu.europa.ec.eudi.walletprovider.domain.EpochSecondsInstant
import eu.europa.ec.eudi.walletprovider.domain.RFC7519
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ChallengeClaims(
    @Required @SerialName(CHALLENGE) val challenge: Base64UrlSafeByteArray,
    @Required @SerialName(RFC7519.NOT_BEFORE) val notBefore: EpochSecondsInstant,
    @Required @SerialName(RFC7519.EXPIRES_AT) val expiresAt: EpochSecondsInstant,
) {
    companion object {
        const val CHALLENGE: String = "challenge"
    }

    override fun equals(other: Any?): Boolean =
        if (other is ChallengeClaims)
            challenge.contentEquals(other.challenge) && notBefore == other.notBefore && expiresAt == other.expiresAt
        else
            false

    override fun hashCode(): Int = 31 * (31 * challenge.contentHashCode() + notBefore.hashCode()) + expiresAt.hashCode()
}

typealias ChallengeAttestation = JwsSigned<ChallengeClaims>

fun ChallengeAttestation.toChallenge(): Challenge = Challenge(serialize().encodeToByteArray())

@JvmInline
@Serializable
value class Challenge(
    val value: Base64UrlSafeByteArray,
) {
    init {
        require(value.isNotEmpty()) { "value must not be empty" }
    }

    override fun toString(): String = value.toString()
}
