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

import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.josef.io.InstantLongSerializer
import eu.europa.ec.eudi.walletprovider.adapter.serialization.UriStringSerializer
import eu.europa.ec.eudi.walletprovider.adapter.serialization.UrlStringSerializer
import kotlinx.serialization.Serializable
import java.net.URI
import java.net.URL
import kotlin.time.Duration
import kotlin.time.Instant

typealias Base64UrlSafeByteArray =
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    ByteArray

typealias EpochSecondsInstant =
    @Serializable(with = InstantLongSerializer::class)
    Instant

@JvmInline
value class ZeroOrPositiveDuration(
    val value: Duration,
) {
    init {
        require(!value.isNegative()) { "value must be positive or 0" }
    }

    override fun toString(): String = value.toString()
}

@JvmInline
value class Length(
    val value: UInt,
) {
    init {
        require(value > 0u) { "value must be greater than 0" }
    }

    override fun toString(): String = value.toString()
}

@JvmInline
value class PositiveDuration(
    val value: Duration,
) {
    init {
        require(value.isPositive()) { "value must be positive" }
    }

    override fun toString(): String = value.toString()
}

@JvmInline
@Serializable
value class NonBlankString(
    val value: String,
) {
    init {
        require(value.isNotBlank()) { "value must not be blank" }
    }

    override fun toString(): String = value
}

fun String.toNonBlankString() = NonBlankString(this)

typealias Issuer = NonBlankString
typealias ClientId = NonBlankString

typealias StringUri =
    @Serializable(with = UriStringSerializer::class)
    URI

typealias StringUrl =
    @Serializable(with = UrlStringSerializer::class)
    URL
