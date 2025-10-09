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

import at.asitplus.attestation.IOSAttestationConfiguration
import at.asitplus.attestation.NoopAttestationService
import at.asitplus.attestation.Warden
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import eu.europa.ec.eudi.walletprovider.adapter.warden.WarderAttestationVerificationService
import eu.europa.ec.eudi.walletprovider.domain.ios.IosEnvironment
import eu.europa.ec.eudi.walletprovider.time.Clock
import eu.europa.ec.eudi.walletprovider.time.toKotlinClock
import io.ktor.server.application.*
import io.ktor.server.plugins.di.dependencies
import kotlinx.datetime.toDeprecatedClock
import org.slf4j.LoggerFactory
import at.asitplus.attestation.AttestationService as WardenAttestationService

fun Application.configureWardenAttestationVerificationModule(config: AttestationVerificationConfiguration) {
    configureWardenAttestationService(config)
    configureWardenAttestationVerificationService()
}

private val logger = LoggerFactory.getLogger("WardenAttestationVerificationModule")

private fun Application.configureWardenAttestationService(config: AttestationVerificationConfiguration) {
    dependencies {
        provide<WardenAttestationService> {
            when (config) {
                AttestationVerificationConfiguration.Disabled -> {
                    logger.warn("Attestation Verification is currently disabled")
                    NoopAttestationService
                }

                is AttestationVerificationConfiguration.Enabled -> {
                    val androidAttestation: AndroidAttestationConfiguration =
                        with(config.androidAttestation) {
                            AndroidAttestationConfiguration(
                                applications =
                                    applications.map { application ->
                                        AndroidAttestationConfiguration.AppData(
                                            packageName = application.packageName.value,
                                            signatureDigests = application.signingCertificateDigests,
                                        )
                                    },
                                requireStrongBox = strongBoxRequired,
                                allowBootloaderUnlock = unlockedBootloaderAllowed,
                                requireRollbackResistance = rollbackResistanceRequired,
                                ignoreLeafValidity = leafCertificateValidityIgnored,
                                verificationSecondsOffset = verificationSkew.inWholeSeconds,
                                attestationStatementValiditySeconds =
                                    when (attestationStatementValidity) {
                                        AttestationStatementValidity.Ignored -> null
                                        is AttestationStatementValidity.Enforced -> attestationStatementValidity.skew.inWholeSeconds
                                    },
                                disableHardwareAttestation = !hardwareAttestationEnabled,
                                enableNougatAttestation = nougatAttestationEnabled,
                                enableSoftwareAttestation = softwareAttestationEnabled,
                            )
                        }

                    val iosAttestation: IOSAttestationConfiguration =
                        with(config.iosAttestation) {
                            IOSAttestationConfiguration(
                                applications =
                                    applications.map { application ->
                                        IOSAttestationConfiguration.AppData(
                                            teamIdentifier = application.team.value,
                                            bundleIdentifier = application.bundle.value,
                                            sandbox =
                                                when (application.environment) {
                                                    IosEnvironment.Production -> false
                                                    IosEnvironment.Sandbox -> true
                                                },
                                        )
                                    },
                                attestationStatementValiditySeconds = attestationStatementValiditySkew.inWholeSeconds,
                            )
                        }

                    Warden(
                        androidAttestationConfiguration = androidAttestation,
                        iosAttestationConfiguration = iosAttestation,
                        clock = resolve<Clock>().toKotlinClock().toDeprecatedClock(),
                        verificationTimeOffset = config.verificationTimeSkew,
                    )
                }
            }
        }
    }
}

private fun Application.configureWardenAttestationVerificationService() {
    val wardenAttestationService: WardenAttestationService by dependencies
    val wardenAttestationVerificationService = WarderAttestationVerificationService(wardenAttestationService)
    dependencies {
        provide { wardenAttestationVerificationService }
        provide { wardenAttestationVerificationService.validateKeyAttestation }
    }
}
