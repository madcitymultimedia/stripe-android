package com.stripe.android.payments.core.authentication

import androidx.annotation.ColorInt
import androidx.annotation.VisibleForTesting
import androidx.core.graphics.toColorInt
import androidx.fragment.app.DialogFragment
import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleObserver
import androidx.lifecycle.OnLifecycleEvent
import com.stripe.android.PaymentAuthConfig
import com.stripe.android.PaymentRelayStarter
import com.stripe.android.StripePaymentController
import com.stripe.android.exception.StripeException
import com.stripe.android.model.Stripe3ds2AuthParams
import com.stripe.android.model.Stripe3ds2AuthResult
import com.stripe.android.model.Stripe3ds2Fingerprint
import com.stripe.android.model.StripeIntent
import com.stripe.android.networking.AnalyticsEvent
import com.stripe.android.networking.AnalyticsRequestExecutor
import com.stripe.android.networking.AnalyticsRequestFactory
import com.stripe.android.networking.ApiRequest
import com.stripe.android.networking.StripeRepository
import com.stripe.android.stripe3ds2.service.StripeThreeDs2Service
import com.stripe.android.stripe3ds2.transaction.ChallengeParameters
import com.stripe.android.stripe3ds2.transaction.IntentData
import com.stripe.android.stripe3ds2.transaction.MessageVersionRegistry
import com.stripe.android.stripe3ds2.transaction.SdkTransactionId
import com.stripe.android.stripe3ds2.transaction.Transaction
import com.stripe.android.stripe3ds2.views.ChallengeProgressDialogFragment
import com.stripe.android.view.AuthActivityStarterHost
import kotlinx.coroutines.withContext
import java.security.cert.CertificateException
import kotlin.coroutines.CoroutineContext

/**
 * [IntentAuthenticator] authenticating through Stripe's 3ds2 SDK.
 */
internal class Stripe3DS2Authenticator(
    private val config: PaymentAuthConfig,
    private val stripeRepository: StripeRepository,
    private val webIntentAuthenticator: WebIntentAuthenticator,
    private val paymentRelayStarterFactory: (AuthActivityStarterHost) -> PaymentRelayStarter,
    private val analyticsRequestExecutor: AnalyticsRequestExecutor,
    private val analyticsRequestFactory: AnalyticsRequestFactory,
    private val workContext: CoroutineContext,
    private val uiContext: CoroutineContext,
    private val threeDs2Service: StripeThreeDs2Service,
    private val messageVersionRegistry: MessageVersionRegistry,
    private val challengeProgressActivityStarter: ChallengeProgressActivityStarter
) : IntentAuthenticator {

    override suspend fun authenticate(
        host: AuthActivityStarterHost,
        stripeIntent: StripeIntent,
        threeDs1ReturnUrl: String?,
        requestOptions: ApiRequest.Options
    ) {
        handle3ds2Auth(
            host,
            stripeIntent,
            requestOptions,
            stripeIntent.nextActionData as StripeIntent.NextActionData.SdkData.Use3DS2
        )
    }

    private suspend fun handle3ds2Auth(
        host: AuthActivityStarterHost,
        stripeIntent: StripeIntent,
        requestOptions: ApiRequest.Options,
        nextActionData: StripeIntent.NextActionData.SdkData.Use3DS2
    ) {
        analyticsRequestExecutor.executeAsync(
            analyticsRequestFactory.createRequest(AnalyticsEvent.Auth3ds2Fingerprint)
        )
        try {
            begin3ds2Auth(
                host,
                stripeIntent,
                Stripe3ds2Fingerprint(nextActionData),
                requestOptions
            )
        } catch (e: CertificateException) {
            handleError(
                host,
                StripePaymentController.getRequestCode(stripeIntent),
                e
            )
        }
    }

    private suspend fun handleError(
        host: AuthActivityStarterHost,
        requestCode: Int,
        throwable: Throwable
    ) = withContext(uiContext) {
        paymentRelayStarterFactory(host)
            .start(
                PaymentRelayStarter.Args.ErrorArgs(
                    StripeException.create(throwable),
                    requestCode
                )
            )
    }

    private suspend fun begin3ds2Auth(
        host: AuthActivityStarterHost,
        stripeIntent: StripeIntent,
        stripe3ds2Fingerprint: Stripe3ds2Fingerprint,
        requestOptions: ApiRequest.Options
    ) {
        val stripe3ds2Config = config.stripe3ds2Config
        val transaction = threeDs2Service.createTransaction(
            stripe3ds2Fingerprint.directoryServerEncryption.directoryServerId,
            messageVersionRegistry.current,
            stripeIntent.isLiveMode,
            stripe3ds2Fingerprint.directoryServerName,
            stripe3ds2Fingerprint.directoryServerEncryption.rootCerts,
            stripe3ds2Fingerprint.directoryServerEncryption.directoryServerPublicKey,
            stripe3ds2Fingerprint.directoryServerEncryption.keyId,
            stripe3ds2Config.uiCustomization.uiCustomization
        )

        val paymentRelayStarter = paymentRelayStarterFactory(host)
        val timeout = config.stripe3ds2Config.timeout
        val accentColor =
            stripe3ds2Config.uiCustomization.uiCustomization.accentColor?.let { accentColor ->
                runCatching { accentColor.toColorInt() }.getOrNull()
            }

        showLoadingScreen(
            host,
            stripe3ds2Fingerprint,
            transaction,
            accentColor
        )

        runCatching {
            perform3ds2AuthenticationRequest(
                transaction,
                stripe3ds2Fingerprint,
                requestOptions,
                timeout
            )
        }.fold(
            onSuccess = { authResult ->
                on3ds2AuthSuccess(
                    authResult,
                    transaction,
                    stripe3ds2Fingerprint.source,
                    timeout,
                    paymentRelayStarter,
                    StripePaymentController.getRequestCode(stripeIntent),
                    host,
                    stripeIntent,
                    requestOptions,
                )
            },
            onFailure = { throwable ->
                on3ds2AuthFailure(
                    throwable,
                    StripePaymentController.getRequestCode(stripeIntent),
                    paymentRelayStarter
                )
            }
        )
    }

    private fun showLoadingScreen(
        host: AuthActivityStarterHost,
        stripe3ds2Fingerprint: Stripe3ds2Fingerprint,
        transaction: Transaction,
        @ColorInt accentColor: Int?
    ) {
        when (host) {
            is AuthActivityStarterHost.ActivityHost -> {
                when (val activity = host.activity) {
                    is FragmentActivity -> {
                        challengeProgressActivityStarter.start(
                            activity,
                            stripe3ds2Fingerprint.directoryServerName,
                            accentColor,
                            transaction.sdkTransactionId
                        )
                    }
                    else -> null
                }
            }
            is AuthActivityStarterHost.FragmentHost -> {
                challengeProgressActivityStarter.start(
                    host.fragment.requireActivity(),
                    stripe3ds2Fingerprint.directoryServerName,
                    accentColor,
                    transaction.sdkTransactionId
                )
            }
        }?.let { dialogFragment ->
            host.lifecycle.addObserver(
                object : LifecycleObserver {
                    @OnLifecycleEvent(Lifecycle.Event.ON_STOP)
                    fun onStop() {
                        dialogFragment.dismiss()
                    }
                }
            )
        }
    }

    /**
     * Fire the 3DS2 AReq.
     */
    private suspend fun perform3ds2AuthenticationRequest(
        transaction: Transaction,
        stripe3ds2Fingerprint: Stripe3ds2Fingerprint,
        requestOptions: ApiRequest.Options,
        timeout: Int
    ) = withContext(workContext) {
        val areqParams = transaction.createAuthenticationRequestParameters()

        val authParams = Stripe3ds2AuthParams(
            stripe3ds2Fingerprint.source,
            areqParams.sdkAppId,
            areqParams.sdkReferenceNumber,
            areqParams.sdkTransactionId.value,
            areqParams.deviceData,
            areqParams.sdkEphemeralPublicKey,
            areqParams.messageVersion,
            timeout,
            // We do not currently have a fallback url
            // TODO(smaskell-stripe): Investigate more robust error handling
            returnUrl = null
        )

        requireNotNull(
            stripeRepository.start3ds2Auth(
                authParams,
                requestOptions
            )
        )
    }

    @VisibleForTesting
    internal suspend fun on3ds2AuthSuccess(
        result: Stripe3ds2AuthResult,
        transaction: Transaction,
        sourceId: String,
        timeout: Int,
        paymentRelayStarter: PaymentRelayStarter,
        requestCode: Int,
        host: AuthActivityStarterHost,
        stripeIntent: StripeIntent,
        requestOptions: ApiRequest.Options
    ) {
        val ares = result.ares
        if (ares != null) {
            if (ares.isChallenge) {
                startChallengeFlow(
                    ares,
                    transaction,
                    sourceId,
                    timeout,
                    host,
                    stripeIntent,
                    requestOptions
                )
            } else {
                startFrictionlessFlow(
                    paymentRelayStarter,
                    stripeIntent
                )
            }
        } else if (result.fallbackRedirectUrl != null) {
            on3ds2AuthFallback(
                result.fallbackRedirectUrl,
                host,
                stripeIntent,
                requestOptions
            )
        } else {
            val errorMessage = result.error?.let { error ->
                listOf(
                    "Code: ${error.errorCode}",
                    "Detail: ${error.errorDetail}",
                    "Description: ${error.errorDescription}",
                    "Component: ${error.errorComponent}"
                ).joinToString(separator = ", ")
            } ?: "Invalid 3DS2 authentication response"

            on3ds2AuthFailure(
                RuntimeException(
                    "Error encountered during 3DS2 authentication request. $errorMessage"
                ),
                requestCode,
                paymentRelayStarter
            )
        }
    }

    /**
     * Used when standard 3DS2 authentication mechanisms are unavailable.
     */
    private suspend fun on3ds2AuthFallback(
        fallbackRedirectUrl: String,
        host: AuthActivityStarterHost,
        stripeIntent: StripeIntent,
        requestOptions: ApiRequest.Options
    ) {
        analyticsRequestExecutor.executeAsync(
            analyticsRequestFactory.createRequest(AnalyticsEvent.Auth3ds2Fallback)
        )

        webIntentAuthenticator.beginWebAuth(
            host,
            stripeIntent,
            StripePaymentController.getRequestCode(stripeIntent),
            stripeIntent.clientSecret.orEmpty(),
            fallbackRedirectUrl,
            requestOptions.stripeAccount,
            // 3D-Secure requires cancelling the source when the user cancels auth (AUTHN-47)
            shouldCancelSource = true
        )
    }

    private suspend fun on3ds2AuthFailure(
        throwable: Throwable,
        requestCode: Int,
        paymentRelayStarter: PaymentRelayStarter
    ) = withContext(uiContext) {
        paymentRelayStarter.start(
            PaymentRelayStarter.Args.ErrorArgs(
                StripeException.create(throwable),
                requestCode
            )
        )
    }

    private suspend fun startFrictionlessFlow(
        paymentRelayStarter: PaymentRelayStarter,
        stripeIntent: StripeIntent
    ) = withContext(uiContext) {
        analyticsRequestExecutor.executeAsync(
            analyticsRequestFactory.createRequest(AnalyticsEvent.Auth3ds2Frictionless)
        )
        paymentRelayStarter.start(
            PaymentRelayStarter.Args.create(stripeIntent)
        )
    }

    @VisibleForTesting
    internal suspend fun startChallengeFlow(
        ares: Stripe3ds2AuthResult.Ares,
        transaction: Transaction,
        sourceId: String,
        maxTimeout: Int,
        host: AuthActivityStarterHost,
        stripeIntent: StripeIntent,
        requestOptions: ApiRequest.Options
    ) = withContext(workContext) {
        val intent = when (host) {
            is AuthActivityStarterHost.ActivityHost -> {
                host.activity
            }
            is AuthActivityStarterHost.FragmentHost -> {
                host.fragment.requireActivity()
            }
        }.let {
            transaction.createIntent(
                it,
                ChallengeParameters(
                    acsSignedContent = ares.acsSignedContent,
                    threeDsServerTransactionId = ares.threeDSServerTransId,
                    acsTransactionId = ares.acsTransId
                ),
                maxTimeout,
                IntentData(
                    stripeIntent.clientSecret.orEmpty(),
                    sourceId,
                    requestOptions.apiKey,
                    requestOptions.stripeAccount
                )
            )
        }

        when (host) {
            is AuthActivityStarterHost.ActivityHost -> {
                host.activity.startActivityForResult(intent, REQUEST_CODE)
            }
            is AuthActivityStarterHost.FragmentHost -> {
                host.fragment.startActivityForResult(intent, REQUEST_CODE)
            }
        }
    }

    internal interface ChallengeProgressActivityStarter {
        fun start(
            activity: FragmentActivity,
            directoryServerName: String,
            accentColor: Int?,
            sdkTransactionId: SdkTransactionId
        ): DialogFragment

        fun start(
            fragment: Fragment,
            directoryServerName: String,
            accentColor: Int?,
            sdkTransactionId: SdkTransactionId
        ): DialogFragment
    }

    internal class DefaultChallengeProgressActivityStarter : ChallengeProgressActivityStarter {
        override fun start(
            activity: FragmentActivity,
            directoryServerName: String,
            accentColor: Int?,
            sdkTransactionId: SdkTransactionId
        ): DialogFragment {
            return ChallengeProgressDialogFragment.show(
                activity.supportFragmentManager,
                directoryServerName,
                accentColor,
                sdkTransactionId
            )
        }

        override fun start(
            fragment: Fragment,
            directoryServerName: String,
            accentColor: Int?,
            sdkTransactionId: SdkTransactionId
        ): DialogFragment {
            return ChallengeProgressDialogFragment.show(
                fragment.childFragmentManager,
                directoryServerName,
                accentColor,
                sdkTransactionId
            )
        }
    }

    internal companion object {
        val REQUEST_CODE = 80000
    }
}
