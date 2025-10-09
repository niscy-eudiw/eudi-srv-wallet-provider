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
package eu.europa.ec.eudi.walletprovider.adapter.attestationsigning

import arrow.core.Either
import arrow.core.raise.catch
import arrow.core.raise.either
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.sign.Verifier
import at.asitplus.signum.supreme.sign.verifierFor
import at.asitplus.signum.supreme.sign.verify
import at.asitplus.signum.supreme.signature
import eu.europa.ec.eudi.walletprovider.domain.attestationsigning.AttestationSignatureValidationFailure
import eu.europa.ec.eudi.walletprovider.domain.attestationsigning.AttestationType
import eu.europa.ec.eudi.walletprovider.domain.toNonBlankString
import eu.europa.ec.eudi.walletprovider.port.output.attestationsigning.SignAttestation
import eu.europa.ec.eudi.walletprovider.port.output.attestationsigning.ValidateAttestationSignature
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.json.Json

class AttestationSigningService(
    private val signer: Signer,
    private val certificateChain: CertificateChain?,
    private val json: Json,
) {
    private val verifier: Verifier by lazy {
        signer.signatureAlgorithm.verifierFor(signer.publicKey).getOrThrow()
    }

    val signAttestation: SignAttestation =
        object : SignAttestation {
            override suspend fun <T : Any> invoke(
                attestation: T,
                serializer: SerializationStrategy<T>,
                type: AttestationType,
            ): JwsSigned<T> {
                val header =
                    JwsHeader(
                        algorithm = signer.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
                        certificateChain = certificateChain?.takeIf { it.isNotEmpty() },
                        jsonWebKey =
                            if (certificateChain.isNullOrEmpty())
                                signer.publicKey.toJsonWebKey()
                            else
                                null,
                        type = type.type,
                    )
                val plainSignatureInput =
                    JwsSigned.prepareJwsSignatureInput(
                        header = header,
                        payload = attestation,
                        serializer = serializer,
                        json = json,
                    )
                val signature = signer.sign(plainSignatureInput).signature
                return JwsSigned(header, attestation, signature, plainSignatureInput)
            }
        }

    val validateAttestationSignature: ValidateAttestationSignature =
        object : ValidateAttestationSignature {
            override suspend fun <T : Any> invoke(
                unvalidated: String,
                deserializer: DeserializationStrategy<T>,
            ): Either<AttestationSignatureValidationFailure, JwsSigned<T>> =
                either {
                    val parsed =
                        JwsSigned
                            .deserialize(unvalidated)
                            .getOrElse {
                                raise(
                                    AttestationSignatureValidationFailure.UnparsableAttestation(
                                        "Attestation cannot be parsed".toNonBlankString(),
                                        it,
                                    ),
                                )
                            }

                    verifier
                        .verify(parsed.plainSignatureInput, parsed.signature)
                        .getOrElse {
                            raise(
                                AttestationSignatureValidationFailure.InvalidSignature(
                                    "Attestation signature is invalid".toNonBlankString(),
                                    it,
                                ),
                            )
                        }

                    val payload =
                        catch({
                            json.decodeFromString(deserializer, parsed.payload.decodeToString())
                        }) {
                            raise(
                                AttestationSignatureValidationFailure.UnparsableAttestation(
                                    "Attestation payload cannot be parsed".toNonBlankString(),
                                    it,
                                ),
                            )
                        }

                    JwsSigned(
                        header = parsed.header,
                        payload = payload,
                        plainSignatureInput = parsed.plainSignatureInput,
                        signature = parsed.signature,
                    )
                }
        }
}
