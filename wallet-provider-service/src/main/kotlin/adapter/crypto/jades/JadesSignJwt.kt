/*
 * Copyright (c) 2025-2026 European Commission
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
package eu.europa.ec.eudi.walletprovider.adapter.crypto.jades

import arrow.core.NonEmptyList
import arrow.core.raise.context.result
import arrow.core.toNonEmptyListOrNull
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.toJcaCertificate
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.signature
import eu.europa.ec.eudi.walletprovider.domain.JwtType
import eu.europa.ec.eudi.walletprovider.domain.RFC7515
import eu.europa.ec.eudi.walletprovider.port.output.crypto.SignJwt
import eu.europa.esig.dss.model.DSSDocument
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.serializer
import eu.europa.esig.dss.enumerations.JWSSerializationType as DSSJWSSerializationType
import eu.europa.esig.dss.enumerations.MimeType as DSSMimeType
import eu.europa.esig.dss.enumerations.SignatureAlgorithm as DSSSignatureAlgorithm
import eu.europa.esig.dss.enumerations.SignatureLevel as DSSSignatureLevel
import eu.europa.esig.dss.enumerations.SignaturePackaging as DSSSignaturePackaging
import eu.europa.esig.dss.jades.JAdESSignatureParameters as DSSJAdESSignatureParameters
import eu.europa.esig.dss.jades.signature.JAdESBuilder as DSSJAdESBuilder
import eu.europa.esig.dss.jades.signature.JAdESCompactBuilder as DSSJAdESCompactBuilder
import eu.europa.esig.dss.jades.signature.JAdESLevelBaselineB as DSSJAdESLevelBaselineB
import eu.europa.esig.dss.jades.signature.JAdESService as DSSJAdESService
import eu.europa.esig.dss.jades.validation.JWS as DSSJWS
import eu.europa.esig.dss.model.InMemoryDocument as DSSInMemoryDocument
import eu.europa.esig.dss.model.SignatureValue as DSSSignatureValue
import eu.europa.esig.dss.model.x509.CertificateToken as DSSCertificateToken
import eu.europa.esig.dss.spi.validation.CertificateVerifier as DSSCertificateVerifier
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier as DSSCommonCertificateVerifier

class JadesSignJwt<T : Any> private constructor(
    private val signer: Signer,
    private val certificateChain: NonEmptyList<DSSCertificateToken>,
    type: JwtType,
    private val serializer: SerializationStrategy<T>,
    private val parse: (String) -> JwsCompactTyped<T>,
) : SignJwt<T> {
    override val signingAlgorithm: JwsAlgorithm
        get() = signer.signatureAlgorithm.toJwsAlgorithm().getOrThrow()

    private val service = JAdESService(type, DSSCommonCertificateVerifier())

    override suspend fun invoke(claims: T): JwsCompactTyped<T> {
        val payload = joseCompliantSerializer.encodeToString(serializer, claims).encodeToByteArray()
        val unsignedDocument = DSSInMemoryDocument(payload)
        val parameters =
            DSSJAdESSignatureParameters().apply {
                signatureLevel = DSSSignatureLevel.JAdES_BASELINE_B
                signaturePackaging = DSSSignaturePackaging.ENVELOPING
                jwsSerializationType = DSSJWSSerializationType.COMPACT_SERIALIZATION
                signingCertificate = this@JadesSignJwt.certificateChain.first()
                signingAlgorithm.toDSS().getOrThrow().let {
                    encryptionAlgorithm = it.encryptionAlgorithm
                    digestAlgorithm = it.digestAlgorithm
                }
                this.certificateChain = this@JadesSignJwt.certificateChain.map { it }
            }
        val unsignedData = service.getDataToSign(unsignedDocument, parameters)
        val signature = signer.sign(unsignedData.bytes).signature
        val signedDocument =
            service.signDocument(
                unsignedDocument,
                parameters,
                DSSSignatureValue(signingAlgorithm.toDSS().getOrThrow(), signature.rawByteArray),
            )
        val serializedSignedDocument = signedDocument.openStream().bufferedReader().use { it.readText() }
        return parse(serializedSignedDocument)
    }

    companion object {
        internal suspend inline operator fun <reified T : Any> invoke(
            signer: Signer,
            certificateChain: CertificateChain,
            type: JwtType,
        ): JadesSignJwt<T> {
            val jwsAlgorithm =
                signer.signatureAlgorithm.toJwsAlgorithm().getOrElse {
                    throw IllegalArgumentException("signer is not using a JwsAlgorithm", it)
                }
            val dssAlgorithm =
                jwsAlgorithm.toDSS().getOrElse {
                    throw IllegalArgumentException("signer is not using a JwsAlgorithm supported by DSS", it)
                }
            val certificateChain = certificateChain.map { it.toDSS().getOrThrow() }.toNonEmptyListOrNull()
            requireNotNull(certificateChain) {
                "certificateChain is required for JAdES"
            }

            return JadesSignJwt(
                signer,
                certificateChain,
                type,
                serializer<T>(),
            ) { JwsCompactTyped(it) }
        }
    }
}

private fun JwsAlgorithm.toDSS(): Result<DSSSignatureAlgorithm> =
    result {
        when (this) {
            JwsAlgorithm.MAC.HS256 -> DSSSignatureAlgorithm.HMAC_SHA256
            JwsAlgorithm.MAC.HS384 -> DSSSignatureAlgorithm.HMAC_SHA384
            JwsAlgorithm.MAC.HS512 -> DSSSignatureAlgorithm.HMAC_SHA512
            JwsAlgorithm.Signature.EC.ES256 -> DSSSignatureAlgorithm.ECDSA_SHA256
            JwsAlgorithm.Signature.EC.ES384 -> DSSSignatureAlgorithm.ECDSA_SHA384
            JwsAlgorithm.Signature.EC.ES512 -> DSSSignatureAlgorithm.ECDSA_SHA512
            JwsAlgorithm.Signature.RSA.RS256 -> DSSSignatureAlgorithm.RSA_SHA256
            JwsAlgorithm.Signature.RSA.RS384 -> DSSSignatureAlgorithm.RSA_SHA384
            JwsAlgorithm.Signature.RSA.RS512 -> DSSSignatureAlgorithm.RSA_SHA512
            JwsAlgorithm.Signature.RSA.PS256 -> DSSSignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1
            JwsAlgorithm.Signature.RSA.PS384 -> DSSSignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1
            JwsAlgorithm.Signature.RSA.PS512 -> DSSSignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1
            else -> throw UnsupportedOperationException("Unsupported algorithm: $this")
        }
    }

private suspend fun X509Certificate.toDSS(): Result<DSSCertificateToken> =
    result {
        DSSCertificateToken(toJcaCertificate().getOrThrow())
    }

private class JAdESBaselineB(
    private val type: JwtType,
    certificateVerifier: DSSCertificateVerifier,
    signatureParameters: DSSJAdESSignatureParameters,
    documentsToSign: List<DSSDocument>,
) : DSSJAdESLevelBaselineB(certificateVerifier, signatureParameters, documentsToSign) {
    override fun incorporateType() {
        addHeader(RFC7515.TYPE, type.value)
    }
}

private class JAdESBuilder(
    private val jwtType: JwtType,
    certificateVerifier: DSSCertificateVerifier,
    signatureParameters: DSSJAdESSignatureParameters,
    documentsToSign: List<DSSDocument>,
) : DSSJAdESCompactBuilder(certificateVerifier, signatureParameters, documentsToSign) {
    private val jadesBaselineB = JAdESBaselineB(jwtType, certificateVerifier, signatureParameters, documentsToSign)

    override fun incorporateHeader(jws: DSSJWS) {
        jadesBaselineB.signedProperties.forEach { (claim, value) -> jws.setHeader(claim, value) }
    }

    override fun getMimeType(): DSSMimeType =
        object : DSSMimeType {
            override fun getMimeTypeString(): String = "application/${jwtType.value}"

            override fun getExtension(): String = "jwt"
        }

    override fun incorporatePayload(jws: DSSJWS) {
        val payload = jadesBaselineB.payloadBytes
        if (null != payload && payload.isNotEmpty()) {
            jws.setPayloadOctets(payload)
        }
    }
}

private class JAdESService(
    private val jwtType: JwtType,
    certificateVerifier: DSSCertificateVerifier,
) : DSSJAdESService(certificateVerifier) {
    override fun getJAdESBuilder(
        parameters: DSSJAdESSignatureParameters,
        documentsToSign: List<DSSDocument>,
    ): DSSJAdESBuilder = JAdESBuilder(jwtType, certificateVerifier, parameters, documentsToSign)
}
