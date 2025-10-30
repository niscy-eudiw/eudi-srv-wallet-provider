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
package eu.europa.ec.eudi.walletprovider.port.input.walletapplicationattestation

import arrow.core.Either
import arrow.core.raise.either
import at.asitplus.signum.indispensable.AndroidKeystoreAttestation
import at.asitplus.signum.indispensable.Attestation
import at.asitplus.signum.indispensable.IosHomebrewAttestation
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import eu.europa.ec.eudi.walletprovider.domain.*
import eu.europa.ec.eudi.walletprovider.domain.time.Clock
import eu.europa.ec.eudi.walletprovider.domain.walletapplicationattestation.WalletApplicationAttestation
import eu.europa.ec.eudi.walletprovider.domain.walletapplicationattestation.WalletApplicationAttestationClaims
import eu.europa.ec.eudi.walletprovider.domain.walletapplicationattestation.WalletLink
import eu.europa.ec.eudi.walletprovider.domain.walletapplicationattestation.WalletName
import eu.europa.ec.eudi.walletprovider.domain.walletinformation.GeneralInformation
import eu.europa.ec.eudi.walletprovider.port.output.challenge.ValidateChallenge
import eu.europa.ec.eudi.walletprovider.port.output.jose.SignJwt
import eu.europa.ec.eudi.walletprovider.port.output.keyattestation.KeyAttestationValidationFailure
import eu.europa.ec.eudi.walletprovider.port.output.keyattestation.ValidateKeyAttestation
import kotlinx.serialization.Required
import kotlinx.serialization.Serializable
import kotlin.time.Duration

fun interface IssueWalletApplicationAttestation {
    suspend operator fun invoke(
        request: WalletApplicationAttestationIssuanceRequest,
    ): Either<WalletApplicationAttestationIssuanceFailure, WalletApplicationAttestation>
}

sealed interface WalletApplicationAttestationIssuanceRequest {
    sealed interface PlatformKeyAttestation<out KeyAttestation : Attestation> : WalletApplicationAttestationIssuanceRequest {
        val keyAttestation: KeyAttestation
        val challenge: Challenge

        @Serializable
        data class Android(
            @Required override val keyAttestation: AndroidKeystoreAttestation,
            @Required override val challenge: Challenge,
        ) : PlatformKeyAttestation<AndroidKeystoreAttestation>

        @Serializable
        data class Ios(
            @Required override val keyAttestation: IosHomebrewAttestation,
            @Required override val challenge: Challenge,
        ) : PlatformKeyAttestation<IosHomebrewAttestation>
    }

    @Serializable
    data class Jwk(
        val jwk: JsonWebKey,
    ) : WalletApplicationAttestationIssuanceRequest
}

sealed interface WalletApplicationAttestationIssuanceFailure {
    class InvalidChallenge(
        val error: NonBlankString,
        val cause: Throwable? = null,
    ) : WalletApplicationAttestationIssuanceFailure

    class InvalidKeyAttestation(
        val error: KeyAttestationValidationFailure,
    ) : WalletApplicationAttestationIssuanceFailure
}

@JvmInline
value class WalletApplicationAttestationValidity(
    val value: Duration,
) {
    init {
        require(value.isPositive() && value <= ARF.MAX_WALLET_APPLICATION_ATTESTATION_VALIDITY)
    }

    override fun toString(): String = value.toString()

    companion object {
        val ArfMax: WalletApplicationAttestationValidity =
            WalletApplicationAttestationValidity(ARF.MAX_WALLET_APPLICATION_ATTESTATION_VALIDITY)
    }
}

class IssueWalletApplicationAttestationLive(
    private val clock: Clock,
    private val validateChallenge: ValidateChallenge,
    private val validateKeyAttestation: ValidateKeyAttestation,
    private val validity: WalletApplicationAttestationValidity,
    private val issuer: Issuer,
    private val clientId: ClientId,
    private val walletName: WalletName?,
    private val walletLink: WalletLink?,
    private val generalInformation: GeneralInformation,
    private val signJwt: SignJwt<WalletApplicationAttestationClaims>,
) : IssueWalletApplicationAttestation {
    override suspend fun invoke(
        request: WalletApplicationAttestationIssuanceRequest,
    ): Either<WalletApplicationAttestationIssuanceFailure, WalletApplicationAttestation> =
        either {
            val attestedKey =
                when (request) {
                    is WalletApplicationAttestationIssuanceRequest.PlatformKeyAttestation<*> -> {
                        validateChallenge(request.challenge, clock.now())
                            .mapLeft { WalletApplicationAttestationIssuanceFailure.InvalidChallenge(it.error, it.cause) }
                            .bind()

                        validateKeyAttestation(request.keyAttestation, request.challenge)
                            .mapLeft { WalletApplicationAttestationIssuanceFailure.InvalidKeyAttestation(it) }
                            .bind()
                            .publicKey
                            .toJsonWebKey()
                    }

                    is WalletApplicationAttestationIssuanceRequest.Jwk -> request.jwk
                }

            val issuedAt = clock.now()
            val expiresAt = issuedAt + validity.value
            val walletApplicationAttestation =
                WalletApplicationAttestationClaims(
                    issuer,
                    clientId,
                    expiresAt = expiresAt,
                    ConfirmationClaim(jsonWebKey = attestedKey),
                    issuedAt = issuedAt,
                    notBefore = issuedAt,
                    walletName,
                    walletLink,
                    null,
                    WalletApplicationAttestationClaims.WalletInformation(generalInformation),
                )

            signJwt(walletApplicationAttestation)
        }
}
