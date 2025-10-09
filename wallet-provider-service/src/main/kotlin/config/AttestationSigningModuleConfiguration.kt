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

import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.os.JKSProvider
import at.asitplus.signum.supreme.sign.Signer
import eu.europa.ec.eudi.walletprovider.adapter.attestationsigning.AttestationSigningService
import io.ktor.server.application.*
import io.ktor.server.plugins.di.*
import kotlinx.serialization.json.Json
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.security.KeyStore

suspend fun Application.configureAttestationSigningModule(config: SigningKeyConfiguration) {
    configureAttestationSigningService(config)
}

private suspend fun Application.configureAttestationSigningService(config: SigningKeyConfiguration) {
    val (signer, certificateChain) =
        when (config) {
            SigningKeyConfiguration.GenerateRandom -> generateRandomSigner() to null
            is SigningKeyConfiguration.LoadFromKeystore -> loadSignerAndCertificateChainFromKeystore(config)
        }
    val json: Json by dependencies
    val attestationSigningService = AttestationSigningService(signer, certificateChain, json)
    dependencies {
        provide { attestationSigningService }
        provide { attestationSigningService.signAttestation }
        provide { attestationSigningService.validateAttestationSignature }
    }
}

private fun generateRandomSigner(): Signer =
    Signer
        .Ephemeral {
            ec {
                curve = ECCurve.SECP_256_R_1
            }
        }.getOrThrow()

private suspend fun loadSignerAndCertificateChainFromKeystore(
    config: SigningKeyConfiguration.LoadFromKeystore,
): Pair<Signer, CertificateChain> {
    val keystore =
        Files
            .newInputStream(config.keystoreFile, StandardOpenOption.READ)
            .use { inputStream ->
                KeyStore
                    .getInstance(config.keystoreType.value)
                    .apply {
                        load(inputStream, config.keystorePassword?.value?.toCharArray())
                    }
            }
    val keystoreProvider =
        JKSProvider {
            withBackingObject {
                store = keystore
            }
        }.getOrThrow()
    val signer =
        keystoreProvider
            .getSignerForKey(config.keyAlias.value) {
                when (val signatureAlgorithm = config.algorithm) {
                    is SignatureAlgorithm.ECDSA -> {
                        ec {
                            digest = signatureAlgorithm.digest
                        }
                    }
                    is SignatureAlgorithm.RSA -> {
                        rsa {
                            digest = signatureAlgorithm.digest
                            padding = signatureAlgorithm.padding
                        }
                    }
                }
                privateKeyPassword = config.keyPassword?.value?.toCharArray()
            }.getOrThrow()
    val certificateChain: CertificateChain =
        keystore
            .getCertificateChain(config.keyAlias.value)
            .map {
                X509Certificate.decodeFromDer(it.encoded)
            }.dropRootCaIfNeeded()
    return signer to certificateChain
}

private fun CertificateChain.dropRootCaIfNeeded(): CertificateChain =
    if (size > 1 && last().isSelfSigned())
        dropLast(1)
    else
        this

private fun X509Certificate.isSelfSigned(): Boolean = tbsCertificate.issuerName == tbsCertificate.subjectName
