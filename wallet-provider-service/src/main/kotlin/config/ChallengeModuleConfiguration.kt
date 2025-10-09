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
package eu.europa.ec.eudi.walletprovider.config

import eu.europa.ec.eudi.walletprovider.domain.challenge.Challenge
import eu.europa.ec.eudi.walletprovider.port.input.challenge.GenerateChallenge
import eu.europa.ec.eudi.walletprovider.port.input.challenge.GenerateChallengeLive
import eu.europa.ec.eudi.walletprovider.port.input.challenge.ValidateChallenge
import eu.europa.ec.eudi.walletprovider.port.input.challenge.ValidateChallengeLive
import eu.europa.ec.eudi.walletprovider.port.input.challenge.ValidateChallengeNoop
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.di.dependencies
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory

fun Application.configureChallengeModule(config: WalletProviderConfiguration) {
    configureGenerateChallenge(config.challenge)
    configureValidateChallenge(config.attestationVerification)
    configureChallengeRoutes()
}

private fun Application.configureGenerateChallenge(config: ChallengeConfiguration) {
    dependencies {
        provide<GenerateChallenge> {
            GenerateChallengeLive(
                clock = resolve(),
                length = config.length,
                validity = config.validity,
                signAttestation = resolve(),
            )
        }
    }
}

private val logger = LoggerFactory.getLogger("ChallengeModule")

private fun Application.configureValidateChallenge(config: AttestationVerificationConfiguration) {
    dependencies {
        provide<ValidateChallenge> {
            when (config) {
                AttestationVerificationConfiguration.Disabled -> {
                    logger.warn("Challenge Verification is currently disabled")
                    ValidateChallengeNoop
                }

                is AttestationVerificationConfiguration.Enabled -> ValidateChallengeLive(resolve())
            }
        }
    }
}

private fun Application.configureChallengeRoutes() {
    routing {
        route("/challenge") {
            post {
                val generateChallenge: GenerateChallenge by dependencies
                val challenge = generateChallenge()
                logger.info("Generated new Challenge: {}", challenge)

                call.respond(HttpStatusCode.OK, ChallengeResponse(challenge))
            }
        }
    }
}

@Serializable
private data class ChallengeResponse(
    val challenge: Challenge,
)
