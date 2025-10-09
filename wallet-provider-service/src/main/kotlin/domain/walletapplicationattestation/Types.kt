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
package eu.europa.ec.eudi.walletprovider.domain.walletapplicationattestation

import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.JwsSigned
import eu.europa.ec.eudi.walletprovider.domain.*
import eu.europa.ec.eudi.walletprovider.domain.arf.GeneralInformation
import eu.europa.ec.eudi.walletprovider.domain.keyattestation.KeyAttestationValidationFailure
import eu.europa.ec.eudi.walletprovider.domain.tokenstatuslist.Status
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Duration

@JvmInline
value class WalletApplicationAttestationValidity(
    val value: Duration,
) : Comparable<WalletApplicationAttestationValidity> {
    init {
        require(value.isPositive() && value <= ARF.MAX_WALLET_APPLICATION_ATTESTATION_VALIDITY)
    }

    override fun toString(): String = value.toString()

    override fun compareTo(other: WalletApplicationAttestationValidity): Int = value.compareTo(other.value)

    companion object {
        val ArfMax: WalletApplicationAttestationValidity =
            WalletApplicationAttestationValidity(ARF.MAX_WALLET_APPLICATION_ATTESTATION_VALIDITY)
    }
}

@Serializable
data class WalletInformation(
    @Required @SerialName(ARF.GENERAL_INFO) val generalInformation: GeneralInformation,
)

@Serializable
data class WalletApplicationAttestationClaims(
    @Required @SerialName(RFC7519.ISSUER) val issuer: Issuer,
    @Required @SerialName(RFC7519.SUBJECT) val subject: ClientId,
    @Required @SerialName(RFC7519.EXPIRES_AT) val expiresAt: EpochSecondsInstant,
    @Required @SerialName(RFC7800.CONFIRMATION) val confirmation: ConfirmationClaim,
    @SerialName(RFC7519.ISSUED_AT) val issuedAt: EpochSecondsInstant? = null,
    @SerialName(RFC7519.NOT_BEFORE) val notBefore: EpochSecondsInstant? = null,
    @SerialName(OpenId4VCISpec.WALLET_NAME) val walletName: WalletName? = null,
    @SerialName(OpenId4VCISpec.WALLET_LINK) val walletLink: StringUrl? = null,
    @SerialName(TokenStatusListSpec.STATUS) val status: Status? = null,
    @Required @SerialName(ARF.EUDI_WALLET_INFO) val walletInformation: WalletInformation,
)

typealias WalletApplicationAttestation = JwsSigned<WalletApplicationAttestationClaims>
typealias WalletName = NonBlankString

sealed interface WalletApplicationAttestationGenerationFailure {
    class InvalidChallenge(
        val error: NonBlankString,
        val cause: Throwable? = null,
    ) : WalletApplicationAttestationGenerationFailure

    class InvalidKeyAttestation(
        val error: KeyAttestationValidationFailure,
    ) : WalletApplicationAttestationGenerationFailure
}
