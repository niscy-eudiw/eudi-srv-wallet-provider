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
package eu.europa.ec.eudi.walletprovider.port.input.challenge

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.right
import eu.europa.ec.eudi.walletprovider.domain.RFC7519
import eu.europa.ec.eudi.walletprovider.domain.attestationsigning.AttestationType
import eu.europa.ec.eudi.walletprovider.domain.challenge.Challenge
import eu.europa.ec.eudi.walletprovider.domain.challenge.ChallengeClaims
import eu.europa.ec.eudi.walletprovider.domain.challenge.ChallengeVerificationFailure
import eu.europa.ec.eudi.walletprovider.domain.toNonBlankString
import eu.europa.ec.eudi.walletprovider.port.output.jose.JwtSignatureValidationFailure
import eu.europa.ec.eudi.walletprovider.port.output.jose.ValidateJwtSignature
import kotlin.time.Instant

fun interface ValidateChallenge {
    suspend operator fun invoke(
        challenge: Challenge,
        at: Instant,
    ): Either<ChallengeVerificationFailure, Unit>
}

class ValidateChallengeLive(
    private val validateJwtSignature: ValidateJwtSignature<ChallengeClaims>,
) : ValidateChallenge {
    override suspend fun invoke(
        challenge: Challenge,
        at: Instant,
    ): Either<ChallengeVerificationFailure, Unit> =
        either {
            validateJwtSignature(challenge.value.decodeToString()).fold(
                ifLeft = {
                    val (error, cause) =
                        when (it) {
                            is JwtSignatureValidationFailure.InvalidSignature ->
                                "Challenge is not valid: ${it.error}".toNonBlankString() to it.cause

                            is JwtSignatureValidationFailure.UnparsableJwt ->
                                "Challenge is not valid: ${it.error}".toNonBlankString() to it.cause
                        }
                    raise(ChallengeVerificationFailure(error, cause))
                },
                ifRight = { challengeAttestation ->
                    ensure(challengeAttestation.header.type == AttestationType.ChallengeAttestation.type) {
                        ChallengeVerificationFailure(
                            (
                                "Challenge is not valid, contains invalid `${RFC7519.TYPE}`. " +
                                    "Expected: '${AttestationType.ChallengeAttestation.type}', " +
                                    "found: '${challengeAttestation.header.type ?: ""}'."
                            ).toNonBlankString(),
                        )
                    }

                    ensure(challengeAttestation.payload.notBefore <= at) {
                        ChallengeVerificationFailure("Challenge is not active yet.".toNonBlankString())
                    }

                    ensure(at < challengeAttestation.payload.expiresAt) {
                        ChallengeVerificationFailure("Challenge is expired.".toNonBlankString())
                    }
                },
            )
        }
}

object ValidateChallengeNoop : ValidateChallenge {
    override suspend fun invoke(
        challenge: Challenge,
        at: Instant,
    ): Either<ChallengeVerificationFailure, Unit> = Unit.right()
}
