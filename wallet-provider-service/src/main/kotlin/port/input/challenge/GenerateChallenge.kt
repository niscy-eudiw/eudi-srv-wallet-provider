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

import eu.europa.ec.eudi.walletprovider.domain.Length
import eu.europa.ec.eudi.walletprovider.domain.PositiveDuration
import eu.europa.ec.eudi.walletprovider.domain.attestationsigning.AttestationType
import eu.europa.ec.eudi.walletprovider.domain.challenge.Challenge
import eu.europa.ec.eudi.walletprovider.domain.challenge.ChallengeClaims
import eu.europa.ec.eudi.walletprovider.domain.challenge.toChallenge
import eu.europa.ec.eudi.walletprovider.port.output.attestationsigning.SignAttestation
import eu.europa.ec.eudi.walletprovider.time.Clock
import java.security.SecureRandom
import kotlin.random.asKotlinRandom

fun interface GenerateChallenge {
    suspend operator fun invoke(): Challenge
}

class GenerateChallengeLive(
    private val clock: Clock,
    private val length: Length,
    private val validity: PositiveDuration,
    private val signAttestation: SignAttestation,
) : GenerateChallenge {
    private val secureRandom = SecureRandom().asKotlinRandom()

    override suspend operator fun invoke(): Challenge {
        val now = clock.now()
        val expiresAt = now + validity.value
        val challengeClaims =
            ChallengeClaims(
                challenge = secureRandom.nextBytes(length.value.toInt()),
                notBefore = now,
                expiresAt = expiresAt,
            )
        val challengeAttestation = signAttestation(challengeClaims, ChallengeClaims.serializer(), AttestationType.ChallengeAttestation)
        return challengeAttestation.toChallenge()
    }
}
