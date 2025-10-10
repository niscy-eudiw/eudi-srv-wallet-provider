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
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

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

@Serializable
data class StatusListToken(
    @Required @SerialName(TokenStatusListSpec.INDEX) val index: UInt,
    @Required @SerialName(TokenStatusListSpec.URI) val uri: StringUri,
)

@Serializable
data class Status(
    @Required @SerialName(TokenStatusListSpec.STATUS_LIST) val statusList: StatusListToken,
)

@Serializable
data class WalletInformation(
    @Required @SerialName(ARF.GENERAL_INFO) val generalInformation: GeneralInformation,
)

@Serializable
data class GeneralInformation(
    @Required @SerialName(ARF.WALLET_PROVIDER_NAME) val provider: ProviderName,
    @Required @SerialName(ARF.WALLET_SOLUTION_ID) val id: SolutionId,
    @Required @SerialName(ARF.WALLET_SOLUTION_VERSION) val version: SolutionVersion,
    @Required @SerialName(ARF.WALLET_SOLUTION_CERTIFICATION_INFORMATION) val certification: CertificationInformation,
)

typealias ProviderName = NonBlankString
typealias SolutionId = NonBlankString
typealias SolutionVersion = NonBlankString

@JvmInline
@Serializable
value class CertificationInformation(
    val value: JsonElement,
) {
    init {
        require((value is JsonPrimitive && value.isString && value.content.isNotBlank()) || value is JsonObject)
    }

    override fun toString(): String = value.toString()
}
