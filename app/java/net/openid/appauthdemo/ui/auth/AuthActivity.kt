package net.openid.appauthdemo.ui.auth

import android.annotation.TargetApi
import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.TextUtils
import android.text.TextWatcher
import android.util.Log
import android.view.View
import android.widget.*
import androidx.annotation.AnyThread
import androidx.annotation.ColorRes
import androidx.annotation.MainThread
import androidx.annotation.WorkerThread
import androidx.appcompat.app.AppCompatActivity
import androidx.browser.customtabs.CustomTabsIntent
import com.google.android.material.snackbar.Snackbar
import net.openid.appauth.*
import net.openid.appauth.R
import net.openid.appauth.browser.AnyBrowserMatcher
import net.openid.appauth.browser.BrowserMatcher
import net.openid.appauth.browser.ExactBrowserMatcher
import net.openid.appauthdemo.*
import net.openid.appauthdemo.databinding.ActivityAuthBinding
import net.openid.appauthdemo.ui.main.MainActivity
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Demonstrates the usage of the AppAuth to authorize a user with an OAuth2 / OpenID Connect
 * provider. Based on the configuration provided in `res/raw/auth_config.json`, the code
 * contained here will:
 *
 * - Retrieve an OpenID Connect discovery document for the provider, or use a local static
 *   configuration.
 * - Utilize dynamic client registration, if no static client id is specified.
 * - Initiate the authorization request using the built-in heuristics or a user-selected browser.
 *
 * _NOTE_: From a clean checkout of this project, the authorization service is not configured.
 * Edit `res/raw/auth_config.json` to provide the required configuration properties. See the
 * README.md in the app/ directory for configuration instructions, and the adjacent IDP-specific
 * instructions.
 */
class AuthActivity : AppCompatActivity() {

    private val TAG = "AuthActivity"
    private val EXTRA_FAILED = "failed"
    private val RC_AUTH = 100

    private lateinit var mAuthService: AuthorizationService
    private lateinit var mAuthStateManager: AuthStateManager
    private lateinit var mConfiguration: Configuration

    private val mClientId = AtomicReference<String>()
    private val mAuthRequest = AtomicReference<AuthorizationRequest>()
    private val mAuthIntent = AtomicReference<CustomTabsIntent>()
    private var mAuthIntentLatch = CountDownLatch(1)
    private lateinit var mExecutor: ExecutorService

    private var mUsePendingIntents = false

    private var mBrowserMatcher: BrowserMatcher = AnyBrowserMatcher.INSTANCE

    private lateinit var binding:ActivityAuthBinding
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding= ActivityAuthBinding.inflate(layoutInflater)
        setContentView(binding.root)


        mExecutor = Executors.newSingleThreadExecutor()
        mAuthStateManager = AuthStateManager.getInstance(this)
        mConfiguration = Configuration.getInstance(this)

        if (mAuthStateManager.getCurrent().isAuthorized
            && !mConfiguration.hasConfigurationChanged()
        ) {
            Log.i(TAG, "User is already authenticated, proceeding to token activity")
            startActivity(Intent(this, MainActivity::class.java))
            finish()
            return
        }

        binding.retry.setOnClickListener { view: View? ->
            mExecutor.submit(
                Runnable { this.initializeAppAuth() })
        }
        binding.startAuth.setOnClickListener { view: View? -> startAuth() }

        binding.loginHintValue.addTextChangedListener(
            LoginHintChangeHandler()
        )

        if (!mConfiguration.isValid()) {
            displayError(mConfiguration.getConfigurationError(), false)
            return
        }

        configureBrowserSelector()
        if (mConfiguration.hasConfigurationChanged()) {
            // discard any existing authorization state due to the change of configuration
            Log.i(TAG, "Configuration change detected, discarding old state")
            mAuthStateManager.replace(AuthState())
            mConfiguration.acceptConfiguration()
        }

        if (intent.getBooleanExtra(EXTRA_FAILED, false)) {
            displayAuthCancelled()
        }

        displayLoading("Initializing")
        mExecutor.submit(Runnable { this.initializeAppAuth() })
    }

    override fun onStart() {
        super.onStart()
        if (mExecutor.isShutdown) {
            mExecutor = Executors.newSingleThreadExecutor()
        }
    }

    override fun onStop() {
        super.onStop()
        mExecutor.shutdownNow()
    }

    override fun onDestroy() {
        super.onDestroy()
        if (mAuthService != null) {
            mAuthService?.dispose()
        }
    }

    protected fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent) {
        super.onActivityResult(requestCode, resultCode, data)
        displayAuthOptions()
        if (resultCode == RESULT_CANCELED) {
            displayAuthCancelled()
        } else {
            val intent = Intent(this, TokenActivity::class.java)
            intent.putExtras(data.extras!!)
            startActivity(intent)
        }
    }

    @MainThread
    fun startAuth() {
        displayLoading("Making authorization request")
        mUsePendingIntents =
           binding.pendingIntentsCheckbox.isChecked

        // WrongThread inference is incorrect for lambdas
        // noinspection WrongThread
        mExecutor.submit { doAuth() }
    }

    /**
     * Initializes the authorization service configuration if necessary, either from the local
     * static values or by retrieving an OpenID discovery document.
     */
    @WorkerThread
    private fun initializeAppAuth() {
        Log.i(TAG, "Initializing AppAuth")
        recreateAuthorizationService()
        if (mAuthStateManager.current.authorizationServiceConfiguration != null) {
            // configuration is already created, skip to client initialization
            Log.i(TAG, "auth config already established")
            initializeClient()
            return
        }

        // if we are not using discovery, build the authorization service configuration directly
        // from the static configuration values.
        if (mConfiguration.discoveryUri == null) {
            Log.i(TAG, "Creating auth config from res/raw/auth_config.json")
            val config = AuthorizationServiceConfiguration(
                mConfiguration.authEndpointUri!!,
                mConfiguration.tokenEndpointUri!!,
                mConfiguration.registrationEndpointUri,
                mConfiguration.endSessionEndpoint
            )
            mAuthStateManager.replace(AuthState(config))
            initializeClient()
            return
        }

        // WrongThread inference is incorrect for lambdas
        // noinspection WrongThread
        runOnUiThread { displayLoading("Retrieving discovery document") }
        Log.i(TAG, "Retrieving OpenID discovery doc")
        AuthorizationServiceConfiguration.fetchFromUrl(
            mConfiguration.discoveryUri!!,
            { config: AuthorizationServiceConfiguration?, ex: AuthorizationException? ->
                handleConfigurationRetrievalResult(
                    config,
                    ex
                )
            },
            mConfiguration.connectionBuilder
        )
    }

    @MainThread
    private fun handleConfigurationRetrievalResult(
        config: AuthorizationServiceConfiguration?,
        ex: AuthorizationException?
    ) {
        if (config == null) {
            Log.i(TAG, "Failed to retrieve discovery document", ex)
            displayError("Failed to retrieve discovery document: " + ex!!.message, true)
            return
        }
        Log.i(TAG, "Discovery document retrieved")
        mAuthStateManager.replace(AuthState(config))
        mExecutor.submit { initializeClient() }
    }

    /**
     * Initiates a dynamic registration request if a client ID is not provided by the static
     * configuration.
     */
    @WorkerThread
    private fun initializeClient() {
        if (mConfiguration.clientId != null) {
            Log.i(TAG, "Using static client ID: " + mConfiguration.clientId)
            // use a statically configured client ID
            mClientId.set(mConfiguration.clientId)
            runOnUiThread { initializeAuthRequest() }
            return
        }
        val lastResponse = mAuthStateManager.current.lastRegistrationResponse
        if (lastResponse != null) {
            Log.i(TAG, "Using dynamic client ID: " + lastResponse.clientId)
            // already dynamically registered a client ID
            mClientId.set(lastResponse.clientId)
            runOnUiThread { initializeAuthRequest() }
            return
        }

        // WrongThread inference is incorrect for lambdas
        // noinspection WrongThread
        runOnUiThread { displayLoading("Dynamically registering client") }
        Log.i(TAG, "Dynamically registering client")
        val registrationRequest = RegistrationRequest.Builder(
            mAuthStateManager.current.authorizationServiceConfiguration!!,
            listOf(mConfiguration.redirectUri)
        )
            .setTokenEndpointAuthenticationMethod(ClientSecretBasic.NAME)
            .build()
        mAuthService!!.performRegistrationRequest(
            registrationRequest
        ) { response: RegistrationResponse?, ex: AuthorizationException? ->
            handleRegistrationResponse(
                response,
                ex
            )
        }
    }

    @MainThread
    private fun handleRegistrationResponse(
        response: RegistrationResponse?,
        ex: AuthorizationException?
    ) {
        mAuthStateManager.updateAfterRegistration(response, ex)
        if (response == null) {
            Log.i(TAG, "Failed to dynamically register client", ex)
            displayErrorLater("Failed to register client: " + ex!!.message, true)
            return
        }
        Log.i(TAG, "Dynamically registered client: " + response.clientId)
        mClientId.set(response.clientId)
        initializeAuthRequest()
    }

    /**
     * Enumerates the browsers installed on the device and populates a spinner, allowing the
     * demo user to easily test the authorization flow against different browser and custom
     * tab configurations.
     */
    @MainThread
    private fun configureBrowserSelector() {
        val spinner = binding.browserSelector
        val adapter = BrowserSelectionAdapter(this)
        spinner.adapter = adapter
        spinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(
                parent: AdapterView<*>?,
                view: View,
                position: Int,
                id: Long
            ) {
                val info = adapter.getItem(position)
                if (info == null) {
                    mBrowserMatcher = AnyBrowserMatcher.INSTANCE
                    return
                } else {
                    mBrowserMatcher = ExactBrowserMatcher(info.mDescriptor)
                }
                recreateAuthorizationService()
                createAuthRequest(getLoginHint())
                warmUpBrowser()
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {
                mBrowserMatcher = AnyBrowserMatcher.INSTANCE
            }
        }
    }

    /**
     * Performs the authorization request, using the browser selected in the spinner,
     * and a user-provided `login_hint` if available.
     */
    @WorkerThread
    private fun doAuth() {
        try {
            mAuthIntentLatch.await()
        } catch (ex: InterruptedException) {
            Log.w(TAG, "Interrupted while waiting for auth intent")
        }
        if (mUsePendingIntents) {
            val completionIntent = Intent(this, MainActivity::class.java)
            val cancelIntent = Intent(this, AuthActivity::class.java)
            cancelIntent.putExtra(EXTRA_FAILED, true)
            cancelIntent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            var flags = 0
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                flags = flags or PendingIntent.FLAG_MUTABLE
            }
            mAuthService!!.performAuthorizationRequest(
                mAuthRequest.get(),
                PendingIntent.getActivity(this, 0, completionIntent, flags),
                PendingIntent.getActivity(this, 0, cancelIntent, flags),
                mAuthIntent.get()
            )
        } else {
            val intent = mAuthService!!.getAuthorizationRequestIntent(
                mAuthRequest.get(),
                mAuthIntent.get()
            )
            startActivityForResult(intent, RC_AUTH)
        }
    }

    private fun recreateAuthorizationService() {
        if (mAuthService != null) {
            Log.i(TAG, "Discarding existing AuthService instance")
            mAuthService.dispose()
        }
        mAuthService = createAuthorizationService()
        mAuthRequest.set(null)
        mAuthIntent.set(null)
    }

    private fun createAuthorizationService(): AuthorizationService {
        Log.i(TAG, "Creating authorization service")
        val builder = AppAuthConfiguration.Builder()
        builder.setBrowserMatcher(mBrowserMatcher)
        builder.setConnectionBuilder(mConfiguration.connectionBuilder)
        return AuthorizationService(this, builder.build())
    }

    @MainThread
    private fun displayLoading(loadingMessage: String) {
        binding.loadingContainer.visibility = View.VISIBLE
        binding.authContainer.visibility = View.GONE
        binding.errorContainer.visibility = View.GONE
       binding.loadingDescription.text =
            loadingMessage
    }

    @MainThread
    private fun displayError(error: String, recoverable: Boolean) {
        binding.errorContainer.visibility = View.VISIBLE
        binding.loadingContainer.visibility = View.GONE
        binding.authContainer.visibility = View.GONE
        binding.errorDescription.text = error
        binding.retry.visibility = if (recoverable) View.VISIBLE else View.GONE
    }

    // WrongThread inference is incorrect in this case
    @AnyThread
    private fun displayErrorLater(error: String, recoverable: Boolean) {
        runOnUiThread { displayError(error, recoverable) }
    }

    @MainThread
    private fun initializeAuthRequest() {
        createAuthRequest(getLoginHint())
        warmUpBrowser()
        displayAuthOptions()
    }

    @MainThread
    private fun displayAuthOptions() {
        binding.authContainer.visibility = View.VISIBLE
        binding.loadingContainer.visibility = View.GONE
        binding.errorContainer.visibility = View.GONE
        val state = mAuthStateManager.current
        val config = state.authorizationServiceConfiguration
        var authEndpointStr: String
        authEndpointStr = if (config!!.discoveryDoc != null) {
            "Discovered auth endpoint: \n"
        } else {
            "Static auth endpoint: \n"
        }
        authEndpointStr += config.authorizationEndpoint
        binding.authEndpoint.text = authEndpointStr
        var clientIdStr: String
        clientIdStr = if (state.lastRegistrationResponse != null) {
            "Dynamic client ID: \n"
        } else {
            "Static client ID: \n"
        }
        clientIdStr += mClientId
        binding.clientId.text = clientIdStr
    }

    private fun displayAuthCancelled() {
        Snackbar.make(
           binding.coordinator,
            "Authorization canceled",
            Snackbar.LENGTH_SHORT
        )
            .show()
    }

    private fun warmUpBrowser() {
        mAuthIntentLatch = CountDownLatch(1)
        mExecutor.execute {
            Log.i(TAG, "Warming up browser instance for auth request")
            val intentBuilder =
                mAuthService!!.createCustomTabsIntentBuilder(mAuthRequest.get().toUri())
            intentBuilder.setToolbarColor(getColorCompat(R.color.colorPrimary))
            mAuthIntent.set(intentBuilder.build())
            mAuthIntentLatch.countDown()
        }
    }

    private fun createAuthRequest(loginHint: String?) {
        Log.i(TAG, "Creating auth request for login hint: $loginHint")
        val authRequestBuilder = AuthorizationRequest.Builder(
            mAuthStateManager.current.authorizationServiceConfiguration!!,
            mClientId.get(),
            ResponseTypeValues.CODE,
            mConfiguration.redirectUri
        )
            .setScope(mConfiguration.scope)
        if (!TextUtils.isEmpty(loginHint)) {
            authRequestBuilder.setLoginHint(loginHint)
        }
        mAuthRequest.set(authRequestBuilder.build())
    }

    private fun getLoginHint(): String? {
        return binding.loginHintValue
            .text
            .toString()
            .trim { it <= ' ' }
    }

    @TargetApi(Build.VERSION_CODES.M)
    private fun getColorCompat(@ColorRes color: Int): Int {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            getColor(color)
        } else {
            resources.getColor(color)
        }
    }

    /**
     * Responds to changes in the login hint. After a "debounce" delay, warms up the browser
     * for a request with the new login hint; this avoids constantly re-initializing the
     * browser while the user is typing.
     */
    private class LoginHintChangeHandler internal constructor() : TextWatcher {
        private val mHandler: Handler
        private var mTask: RecreateAuthRequestTask

        init {
            mHandler = Handler(Looper.getMainLooper())
            mTask = RecreateAuthRequestTask()
        }

        override fun beforeTextChanged(cs: CharSequence, start: Int, count: Int, after: Int) {}
        override fun onTextChanged(cs: CharSequence, start: Int, before: Int, count: Int) {
            mTask.cancel()
            mTask = RecreateAuthRequestTask()
            mHandler.postDelayed(mTask, DEBOUNCE_DELAY_MS.toLong())
        }

        override fun afterTextChanged(ed: Editable) {}

        companion object {
            private const val DEBOUNCE_DELAY_MS = 500
        }
    }

     class RecreateAuthRequestTask : Runnable {
        private val mCanceled = AtomicBoolean()
        override fun run() {
            if (mCanceled.get()) {
                return
            }
            createAuthRequest(getLoginHint())
            warmUpBrowser()
        }

        fun cancel() {
            mCanceled.set(true)
        }
    }
}