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

import arrow.core.toNonEmptyListOrNull
import at.asitplus.attestation.AttestationService
import at.asitplus.attestation.IosAttestationConfiguration
import at.asitplus.attestation.NoopAttestationService
import at.asitplus.attestation.Warden
import at.asitplus.attestation.android.AndroidAttestationConfiguration
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.os.JKSProvider
import at.asitplus.signum.supreme.sign.Signer
import eu.europa.ec.eudi.walletprovider.adapter.jose.SignumSignJwt
import eu.europa.ec.eudi.walletprovider.adapter.jose.SignumValidateJwtSignature
import eu.europa.ec.eudi.walletprovider.adapter.keyattestation.WardenValidateKeyAttestation
import eu.europa.ec.eudi.walletprovider.config.IosKeyAttestationConfiguration.ApplicationConfiguration.IosEnvironment
import eu.europa.ec.eudi.walletprovider.domain.AttestationBasedClientAuthenticationSpec
import eu.europa.ec.eudi.walletprovider.domain.JwtType
import eu.europa.ec.eudi.walletprovider.domain.OpenId4VCISpec
import eu.europa.ec.eudi.walletprovider.domain.time.Clock
import eu.europa.ec.eudi.walletprovider.domain.time.toKotlinClock
import eu.europa.ec.eudi.walletprovider.domain.walletinformation.GeneralInformation
import eu.europa.ec.eudi.walletprovider.domain.walletinformation.WalletSecureCryptographicDeviceInformation
import eu.europa.ec.eudi.walletprovider.port.input.challenge.GenerateChallengeLive
import eu.europa.ec.eudi.walletprovider.port.input.walletapplicationattestation.IssueWalletApplicationAttestationLive
import eu.europa.ec.eudi.walletprovider.port.input.walletunitattestation.IssueWalletUnitAttestationLive
import eu.europa.ec.eudi.walletprovider.port.output.challenge.ValidateChallengeLive
import eu.europa.ec.eudi.walletprovider.port.output.challenge.ValidateChallengeNoop
import io.ktor.http.CacheControl.*
import io.ktor.http.content.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.plugins.cachingheaders.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.forwardedheaders.*
import io.ktor.server.plugins.swagger.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.security.KeyStore

private val logger = LoggerFactory.getLogger("WalletProviderApplication")

suspend fun Application.configureWalletProviderApplication(config: WalletProviderConfiguration) {
    logger.info("Configuring Wallet Provider Application using: {}", config)

    val clock = Clock.System
    val json =
        Json {
            ignoreUnknownKeys = true
            prettyPrint = true
        }

    configureServerPlugins(json)

    val (signer, certificateChain) =
        when (val config = config.signingKey) {
            SigningKeyConfiguration.GenerateRandom -> generateRandomSigner() to null
            is SigningKeyConfiguration.LoadFromKeystore -> loadSignerAndCertificateChainFromKeystore(config)
        }

    val generateChallenge =
        GenerateChallengeLive(
            clock = clock,
            length = config.challenge.length,
            validity = config.challenge.validity,
            signJwt = SignumSignJwt(signer, certificateChain, JwtType(GenerateChallengeLive.CHALLENGE_JWT_TYPE), json),
        )

    val validateChallenge =
        when (config.platformKeyAttestationValidation) {
            PlatformKeyAttestationValidationConfiguration.Disabled -> {
                logger.warn("Challenge Validation is currently disabled")
                ValidateChallengeNoop
            }

            is PlatformKeyAttestationValidationConfiguration.Enabled -> ValidateChallengeLive(SignumValidateJwtSignature(signer, json))
        }

    val wardenAttestationService = createWardenAttestationService(config, clock)
    val validateKeyAttestation = WardenValidateKeyAttestation(wardenAttestationService)

    val issueWalletApplicationAttestation =
        IssueWalletApplicationAttestationLive(
            clock,
            validateChallenge,
            validateKeyAttestation,
            config.walletApplicationAttestation.validity,
            config.issuer,
            config.walletApplicationAttestation.walletName,
            config.walletApplicationAttestation.walletLink,
            GeneralInformation(
                provider = config.walletInformation.generalInformation.provider,
                id = config.walletInformation.generalInformation.id,
                version = config.walletInformation.generalInformation.version,
                certification = config.walletInformation.generalInformation.certification,
            ),
            SignumSignJwt(
                signer,
                certificateChain,
                JwtType(AttestationBasedClientAuthenticationSpec.CLIENT_ATTESTATION_JWT_TYPE),
                json,
            ),
        )

    val issueWalletUnitAttestation =
        IssueWalletUnitAttestationLive(
            clock,
            validateChallenge,
            validateKeyAttestation,
            config.walletUnitAttestation.validity,
            config.issuer,
            keyStorage = config.walletUnitAttestation.keyStorage?.toNonEmptyListOrNull(),
            userAuthentication = config.walletUnitAttestation.userAuthentication?.toNonEmptyListOrNull(),
            config.walletUnitAttestation.certification,
            GeneralInformation(
                provider = config.walletInformation.generalInformation.provider,
                id = config.walletInformation.generalInformation.id,
                version = config.walletInformation.generalInformation.version,
                certification = config.walletInformation.generalInformation.certification,
            ),
            WalletSecureCryptographicDeviceInformation(
                config.walletInformation.walletSecureCryptographicDeviceInformation.type,
                config.walletInformation.walletSecureCryptographicDeviceInformation.certification,
            ),
            SignumSignJwt(
                signer,
                certificateChain,
                JwtType(OpenId4VCISpec.KEY_ATTESTATION_JWT_TYPE),
                json,
            ),
        )

    configureChallengeRoutes(generateChallenge)
    configureWalletApplicationAttestationRoutes(issueWalletApplicationAttestation)
    configureWalletUnitAttestationRoutes(issueWalletUnitAttestation)
}

private fun Application.configureServerPlugins(json: Json) {
    install(ContentNegotiation) {
        json(json)
    }

    install(CachingHeaders) {
        options { _, _ ->
            CachingOptions(NoStore(Visibility.Private))
        }
    }

    install(XForwardedHeaders)
    install(ForwardedHeaders)

    routing {
        swaggerUI(path = "/swagger", swaggerFile = "openapi/openapi.json")
        get("/") {
            call.respondRedirect("/swagger")
        }
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

private fun createWardenAttestationService(
    config: WalletProviderConfiguration,
    clock: Clock,
): AttestationService =
    when (config.platformKeyAttestationValidation) {
        PlatformKeyAttestationValidationConfiguration.Disabled -> {
            logger.warn("Platform Key Attestation Validation is currently disabled")
            NoopAttestationService
        }

        is PlatformKeyAttestationValidationConfiguration.Enabled -> {
            val androidAttestation =
                with(config.platformKeyAttestationValidation.android) {
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

            val iosAttestation =
                with(config.platformKeyAttestationValidation.ios) {
                    IosAttestationConfiguration(
                        applications =
                            applications.map { application ->
                                IosAttestationConfiguration.AppData(
                                    teamIdentifier = application.team.value,
                                    bundleIdentifier = application.bundle.value,
                                    sandbox = IosEnvironment.Sandbox == application.environment,
                                )
                            },
                        attestationStatementValiditySeconds = attestationStatementValiditySkew.inWholeSeconds,
                    )
                }

            Warden(
                androidAttestationConfiguration = androidAttestation,
                iosAttestationConfiguration = iosAttestation,
                clock = clock.toKotlinClock(),
                verificationTimeOffset = config.platformKeyAttestationValidation.verificationTimeSkew,
            )
        }
    }
