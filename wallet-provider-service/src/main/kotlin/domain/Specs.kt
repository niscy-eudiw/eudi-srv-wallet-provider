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
package eu.europa.ec.eudi.walletprovider.domain

import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours

object AttestationBasedClientAuthenticationSpec {
    const val CLIENT_ATTESTATION_JWT_TYPE: String = "oauth-client-attestation+jwt"
}

object RFC7519 {
    const val TYPE: String = "typ"
    const val CONTENT_TYPE: String = "cty"

    const val ISSUER: String = "iss"
    const val SUBJECT: String = "sub"
    const val EXPIRES_AT: String = "exp"
    const val ISSUED_AT: String = "iat"
    const val NOT_BEFORE: String = "nbf"
}

object RFC7800 {
    const val CONFIRMATION: String = "cnf"
}

object ARF {
    const val EUDI_WALLET_INFO: String = "eudi_wallet_info"
    const val GENERAL_INFO: String = "general_info"
    const val WALLET_PROVIDER_NAME: String = "wallet_provider_name"
    const val WALLET_SOLUTION_ID: String = "wallet_solution_id"
    const val WALLET_SOLUTION_VERSION: String = "wallet_solution_version"
    const val WALLET_SOLUTION_CERTIFICATION_INFORMATION: String = "wallet_solution_certification_information"
    val MAX_WALLET_APPLICATION_ATTESTATION_VALIDITY: Duration = 24.hours
}

object TokenStatusListSpec {
    const val STATUS: String = "status"
    const val STATUS_LIST: String = "status_list"
    const val INDEX: String = "idx"
    const val URI: String = "uri"
}

object OpenId4VCISpec {
    const val WALLET_NAME: String = "wallet_name"
    const val WALLET_LINK: String = "wallet_link"
}
