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

import eu.europa.ec.eudi.walletprovider.domain.keyattestation.KeyAttestationValidationFailure
import eu.europa.ec.eudi.walletprovider.domain.walletapplicationattestation.WalletApplicationAttestation
import eu.europa.ec.eudi.walletprovider.domain.walletapplicationattestation.WalletApplicationAttestationGenerationFailure
import eu.europa.ec.eudi.walletprovider.port.input.walletapplicationattestation.GenerateWalletApplicationAttestation
import eu.europa.ec.eudi.walletprovider.port.input.walletapplicationattestation.WalletApplicationAttestationRequest
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.slf4j.Logger
import org.slf4j.LoggerFactory

fun Application.configureWalletApplicationAttestationRoutes(generateWalletApplicationAttestation: GenerateWalletApplicationAttestation) {
    routing {
        route("/wallet-application-attestation") {
            route("/android") {
                post {
                    context(generateWalletApplicationAttestation) {
                        call.generateClientAttestation<WalletApplicationAttestationRequest.Android>()
                    }
                }
            }
            route("/ios") {
                post {
                    context(generateWalletApplicationAttestation) {
                        call.generateClientAttestation<WalletApplicationAttestationRequest.Ios>()
                    }
                }
            }
        }
    }
}

private val logger = LoggerFactory.getLogger("WalletApplicationAttestationRoutes")

context(generateWalletApplicationAttestation: GenerateWalletApplicationAttestation)
private suspend inline fun <reified REQUEST : WalletApplicationAttestationRequest<*>> RoutingCall.generateClientAttestation() {
    val request = receive<REQUEST>()
    logger.info("Received WalletApplicationAttestationRequest: {}", request)

    generateWalletApplicationAttestation(request)
        .fold(
            ifRight = { walletApplicationAttestation ->
                logger.info("Successfully generated WalletApplicationAttestation: {}", walletApplicationAttestation)
                respond(HttpStatusCode.OK, walletApplicationAttestation.toWalletApplicationAttestationResponse())
            },
            ifLeft = { failure ->
                context(logger) {
                    failure.log()
                }
                respond(HttpStatusCode.BadRequest, failure.toWalletApplicationAttestationErrorResponse())
            },
        )
}

context(logger: Logger)
private fun WalletApplicationAttestationGenerationFailure.log() {
    val (error, cause) =
        when (this) {
            is WalletApplicationAttestationGenerationFailure.InvalidChallenge ->
                "WalletApplicationAttestationRequest verification failed, " +
                    "Challenge is not valid: $error" to
                    cause

            is WalletApplicationAttestationGenerationFailure.InvalidKeyAttestation -> {
                when (val keyAttestationFailure = error) {
                    is KeyAttestationValidationFailure.InvalidKeyAttestation ->
                        "WalletApplicationAttestationRequest verification failed, " +
                            "Key Attestation is not valid: ${keyAttestationFailure.error}" to
                            keyAttestationFailure.cause

                    is KeyAttestationValidationFailure.UnsupportedAttestedKey ->
                        "WalletApplicationAttestationRequest verification failed, " +
                            "Key Attestation contains an unsupported PublicKey: ${keyAttestationFailure.error}" to
                            keyAttestationFailure.cause
                }
            }
        }

    logger.warn(error, cause)
}

@Serializable
private data class WalletApplicationAttestationResponse(
    @Required val walletApplicationAttestation: String,
) {
    constructor(walletApplicationAttestation: WalletApplicationAttestation) : this(walletApplicationAttestation.serialize())
}

private fun WalletApplicationAttestation.toWalletApplicationAttestationResponse(): WalletApplicationAttestationResponse =
    WalletApplicationAttestationResponse(this)

@Serializable
private enum class WalletApplicationAttestationError {
    @SerialName("invalid_challenge")
    InvalidChallenge,

    @SerialName("invalid_key_attestation")
    InvalidKeyAttestation,

    @SerialName("unsupported_attested_key")
    UnsupportedAttestedKey,
}

@Serializable
private data class WalletApplicationAttestationErrorResponse(
    @Required val error: WalletApplicationAttestationError,
)

private fun WalletApplicationAttestationGenerationFailure.toWalletApplicationAttestationErrorResponse():
    WalletApplicationAttestationErrorResponse =
    when (this) {
        is WalletApplicationAttestationGenerationFailure.InvalidChallenge -> WalletApplicationAttestationError.InvalidChallenge
        is WalletApplicationAttestationGenerationFailure.InvalidKeyAttestation ->
            when (error) {
                is KeyAttestationValidationFailure.InvalidKeyAttestation -> WalletApplicationAttestationError.InvalidKeyAttestation
                is KeyAttestationValidationFailure.UnsupportedAttestedKey -> WalletApplicationAttestationError.UnsupportedAttestedKey
            }
    }.let { WalletApplicationAttestationErrorResponse(it) }
