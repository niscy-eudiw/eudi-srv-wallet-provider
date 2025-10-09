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
package eu.europa.ec.eudi.walletprovider.domain.attestationsigning

import eu.europa.ec.eudi.walletprovider.domain.AttestationBasedClientAuthenticationSpec
import eu.europa.ec.eudi.walletprovider.domain.NonBlankString

@JvmInline
value class AttestationType private constructor(
    val type: String,
) {
    init {
        require(type.isNotBlank()) { "type must not be blank" }
    }

    override fun toString(): String = type

    companion object {
        val WalletApplicationAttestation: AttestationType =
            AttestationType(AttestationBasedClientAuthenticationSpec.CLIENT_ATTESTATION_JWT_TYPE)
        val ChallengeAttestation = AttestationType("challenge+jwt")
    }
}

sealed interface AttestationSignatureValidationFailure {
    class UnparsableAttestation(
        val error: NonBlankString,
        val cause: Throwable? = null,
    ) : AttestationSignatureValidationFailure

    class InvalidSignature(
        val error: NonBlankString,
        val cause: Throwable? = null,
    ) : AttestationSignatureValidationFailure
}
