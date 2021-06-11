package com.stripe.android.payments

import com.stripe.android.Logger
import com.stripe.android.StripeIntentResult
import com.stripe.android.exception.StripeException
import com.stripe.android.networking.AnalyticsEvent
import com.stripe.android.networking.AnalyticsRequestExecutor
import com.stripe.android.networking.AnalyticsRequestFactory
import com.stripe.android.networking.ApiRequest
import com.stripe.android.networking.RetryDelaySupplier
import com.stripe.android.networking.StripeRepository
import com.stripe.android.stripe3ds2.transaction.ChallengeResult
import kotlinx.coroutines.delay

internal interface Stripe3ds2CompletionRepository {
    suspend fun complete(
        challengeResult: ChallengeResult
    ): PaymentFlowResult.Unvalidated
}

internal class DefaultStripe3ds2CompletionRepository(
    private val stripeRepository: StripeRepository,
    private val analyticsRequestExecutor: AnalyticsRequestExecutor,
    private val analyticsRequestFactory: AnalyticsRequestFactory,
    private val retryDelaySupplier: RetryDelaySupplier = RetryDelaySupplier(),
    enableLogging: Boolean
) : Stripe3ds2CompletionRepository {
    private val logger = Logger.getInstance(enableLogging)

    override suspend fun complete(challengeResult: ChallengeResult): PaymentFlowResult.Unvalidated {
        when (challengeResult) {
            is ChallengeResult.Succeeded -> {
                analyticsRequestExecutor.executeAsync(
                    analyticsRequestFactory.create3ds2Challenge(
                        AnalyticsEvent.Auth3ds2ChallengeCompleted,
                        challengeResult.uiTypeCode
                    )
                )
            }
            is ChallengeResult.Failed -> {
                analyticsRequestExecutor.executeAsync(
                    analyticsRequestFactory.create3ds2Challenge(
                        AnalyticsEvent.Auth3ds2ChallengeCompleted,
                        challengeResult.uiTypeCode
                    )
                )
            }
            is ChallengeResult.Canceled -> {
                analyticsRequestExecutor.executeAsync(
                    analyticsRequestFactory.create3ds2Challenge(
                        AnalyticsEvent.Auth3ds2ChallengeCanceled,
                        challengeResult.uiTypeCode
                    )
                )
            }
            is ChallengeResult.ProtocolError -> {
                analyticsRequestExecutor.executeAsync(
                    analyticsRequestFactory.createRequest(AnalyticsEvent.Auth3ds2ChallengeErrored)
                )
            }
            is ChallengeResult.RuntimeError -> {
                analyticsRequestExecutor.executeAsync(
                    analyticsRequestFactory.createRequest(AnalyticsEvent.Auth3ds2ChallengeErrored)
                )
            }
            is ChallengeResult.Timeout -> {
                analyticsRequestExecutor.executeAsync(
                    analyticsRequestFactory.create3ds2Challenge(
                        AnalyticsEvent.Auth3ds2ChallengeTimedOut,
                        challengeResult.uiTypeCode
                    )
                )
            }
        }

        analyticsRequestExecutor.executeAsync(
            analyticsRequestFactory.create3ds2Challenge(
                AnalyticsEvent.Auth3ds2ChallengePresented,
                challengeResult.initialUiType?.code.orEmpty()
            )
        )

        val requestOptions = ApiRequest.Options(
            challengeResult.intentData.publishableKey,
            challengeResult.intentData.accountId
        )

        complete3ds2Auth(challengeResult, requestOptions)

        return PaymentFlowResult.Unvalidated(
            clientSecret = challengeResult.intentData.clientSecret,
            stripeAccountId = requestOptions.stripeAccount,
            flowOutcome = when (challengeResult) {
                is ChallengeResult.Succeeded -> {
                    StripeIntentResult.Outcome.SUCCEEDED
                }
                is ChallengeResult.Failed -> {
                    StripeIntentResult.Outcome.FAILED
                }
                is ChallengeResult.Canceled -> {
                    StripeIntentResult.Outcome.CANCELED
                }
                is ChallengeResult.ProtocolError -> {
                    StripeIntentResult.Outcome.FAILED
                }
                is ChallengeResult.RuntimeError -> {
                    StripeIntentResult.Outcome.FAILED
                }
                is ChallengeResult.Timeout -> {
                    StripeIntentResult.Outcome.TIMEDOUT
                }
            }
        )
    }

    /**
     * Call [StripeRepository.complete3ds2Auth] to notify the Stripe API that the 3DS2
     * challenge has been completed.
     *
     * When successful, call [startCompletionActivity] to return the result.
     *
     * When [StripeRepository.complete3ds2Auth] fails, handle in [onComplete3ds2AuthFailure].
     *
     * @param flowOutcome the outcome of the 3DS2 challenge flow.
     * @param remainingRetries the number of retry attempts remaining. Defaults to [MAX_RETRIES].
     */
    private suspend fun complete3ds2Auth(
        challengeResult: ChallengeResult,
        requestOptions: ApiRequest.Options,
        remainingRetries: Int = MAX_RETRIES,
    ) {
        // ignore result
        runCatching {
            stripeRepository.complete3ds2Auth(
                challengeResult.intentData.sourceId,
                requestOptions
            )
        }.fold(
            onSuccess = {
                val attemptedRetries = MAX_RETRIES - remainingRetries
                logger.debug(
                    "3DS2 challenge completion request was successful. " +
                        "$attemptedRetries retries attempted."
                )
            },
            onFailure = { error ->
                onComplete3ds2AuthFailure(
                    challengeResult,
                    requestOptions,
                    remainingRetries,
                    error
                )
            }
        )
    }

    /**
     * When [StripeRepository.complete3ds2Auth] fails with a client error (a 4xx status code)
     * and [remainingRetries] is greater than 0, retry after a delay.
     *
     * The delay logic can be found in [RetryDelaySupplier.getDelayMillis].
     *
     * @param flowOutcome the outcome of the 3DS2 challenge flow.
     * @param remainingRetries the number of retry attempts remaining. Defaults to [MAX_RETRIES].
     */
    private suspend fun onComplete3ds2AuthFailure(
        challengeResult: ChallengeResult,
        requestOptions: ApiRequest.Options,
        remainingRetries: Int,
        error: Throwable,
    ) {
        logger.error(
            "3DS2 challenge completion request failed. Remaining retries: $remainingRetries",
            error
        )

        val isClientError = when (error) {
            is StripeException -> error.isClientError
            else -> false
        }
        val shouldRetry = remainingRetries > 0 && isClientError

        if (shouldRetry) {
            delay(
                retryDelaySupplier.getDelayMillis(
                    MAX_RETRIES,
                    remainingRetries
                )
            )

            // attempt request with a decremented `retries`
            complete3ds2Auth(
                challengeResult,
                requestOptions,
                remainingRetries = remainingRetries - 1
            )
        } else {
            logger.debug(
                "Did not make a successful 3DS2 challenge completion request after retrying."
            )
        }
    }

    private companion object {
        private const val MAX_RETRIES = 3
    }
}
