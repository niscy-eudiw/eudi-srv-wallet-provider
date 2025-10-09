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
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import eu.europa.ec.eudi.walletprovider.domain.*
import eu.europa.ec.eudi.walletprovider.domain.attestationsigning.AttestationType
import eu.europa.ec.eudi.walletprovider.domain.challenge.Challenge
import eu.europa.ec.eudi.walletprovider.domain.walletapplicationattestation.*
import eu.europa.ec.eudi.walletprovider.port.input.challenge.ValidateChallenge
import eu.europa.ec.eudi.walletprovider.port.output.attestationsigning.SignAttestation
import eu.europa.ec.eudi.walletprovider.port.output.keyattestation.ValidateKeyAttestation
import eu.europa.ec.eudi.walletprovider.time.Clock
import kotlinx.serialization.Required
import kotlinx.serialization.Serializable

sealed interface WalletApplicationAttestationRequest<out KeyAttestation : Attestation> {
    val keyAttestation: KeyAttestation
    val challenge: Challenge
    val clientId: ClientId

    @Serializable
    data class Android(
        @Required override val keyAttestation: AndroidKeystoreAttestation,
        @Required override val challenge: Challenge,
        @Required override val clientId: ClientId,
    ) : WalletApplicationAttestationRequest<AndroidKeystoreAttestation>

    @Serializable
    data class Ios(
        @Required override val keyAttestation: IosHomebrewAttestation,
        @Required override val challenge: Challenge,
        @Required override val clientId: ClientId,
    ) : WalletApplicationAttestationRequest<IosHomebrewAttestation>
}

fun interface GenerateWalletApplicationAttestation {
    suspend operator fun invoke(
        request: WalletApplicationAttestationRequest<*>,
    ): Either<WalletApplicationAttestationGenerationFailure, WalletApplicationAttestation>
}

class GenerateWalletApplicationAttestationLive(
    private val clock: Clock,
    private val validateChallenge: ValidateChallenge,
    private val validateKeyAttestation: ValidateKeyAttestation,
    private val validity: WalletApplicationAttestationValidity,
    private val issuer: Issuer,
    private val walletName: WalletName?,
    private val walletLink: StringUrl?,
    private val walletInformation: WalletInformation,
    private val signAttestation: SignAttestation,
) : GenerateWalletApplicationAttestation {
    override suspend fun invoke(
        request: WalletApplicationAttestationRequest<*>,
    ): Either<WalletApplicationAttestationGenerationFailure, WalletApplicationAttestation> =
        either {
            val now = clock.now()
            validateChallenge(request.challenge, now)
                .mapLeft { WalletApplicationAttestationGenerationFailure.InvalidChallenge(it.error, it.cause) }
                .bind()

            val attestedKey =
                validateKeyAttestation(request.keyAttestation, request.challenge)
                    .mapLeft { WalletApplicationAttestationGenerationFailure.InvalidKeyAttestation(it) }
                    .bind()
                    .publicKey

            val issuedAt = clock.now()
            val expiresAt = issuedAt + validity.value
            val clientAttestation =
                WalletApplicationAttestationClaims(
                    issuer,
                    request.clientId,
                    expiresAt = expiresAt,
                    ConfirmationClaim(jsonWebKey = attestedKey.toJsonWebKey()),
                    issuedAt = issuedAt,
                    notBefore = issuedAt,
                    walletName = walletName,
                    walletLink = walletLink,
                    walletInformation = walletInformation,
                )

            signAttestation(
                clientAttestation,
                WalletApplicationAttestationClaims.serializer(),
                AttestationType.WalletApplicationAttestation,
            )
        }
}
