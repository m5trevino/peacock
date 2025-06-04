setTimeout(function() {
    Java.perform(function() {
        console.log('[*] Starting universal security bypass script...');
        
        /**
         * 1. Universal SSL Pinning Bypass (Conscrypt)
         */
        try {
            var ConscryptTrustManager = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            var ArrayList = Java.use("java.util.ArrayList");

            // For Android 7+ (TrustManagerImpl)
            ConscryptTrustManager.checkTrustedRecursive.implementation = function(a1, a2, a3, a4, a5, a6) {
                console.log('[+] Bypassing SSL Pinning (TrustManagerImpl)');
                return ArrayList.$new();
            };

            console.log('[+] TrustManagerImpl pinning bypass applied');
        } catch (e) {
            console.log('[-] TrustManagerImpl bypass not loaded:', e);
        }

        /**
         * 2. OkHttp3 Pinning Bypass
         */
        try {
            var OkHttpCertificatePinner = Java.use('okhttp3.CertificatePinner');
            
            // For OkHttp 3.x
            OkHttpCertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(host, peerCertificates) {
                console.log('[+] OkHttp3 check() called with host: ' + host);
                // Do nothing => skip the pinning check
                return;
            };
            // Sometimes used with a different overload
            OkHttpCertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(host, peerCertificates) {
                console.log('[+] OkHttp3 check() called (cert array) with host: ' + host);
                return;
            };

            console.log('[+] OkHttp3 pinning bypass applied');
        } catch (e) {
            console.log('[-] OkHttp3 bypass not loaded:', e);
        }

        /**
         * 3. TrustKit Pinning Bypass
         */
        try {
            var TrustKitVerifier = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
            TrustKitVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(hostname, session) {
                console.log('[+] TrustKit verify() called with host: ' + hostname);
                return true;
            };

            console.log('[+] TrustKit pinning bypass applied');
        } catch (e) {
            console.log('[-] TrustKit bypass not loaded:', e);
        }

        /**
         * 4. Custom SSL / X509TrustManager (bypass if the app uses a custom manager)
         */
        try {
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var SSLContext = Java.use('javax.net.ssl.SSLContext');
            
            // Create a new TrustManager that trusts everything
            var TrustManager = Java.registerClass({
                name: 'com.android.cert.OverrideTrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {
                        // Skip
                    },
                    checkServerTrusted: function(chain, authType) {
                        // Skip
                    },
                    getAcceptedIssuers: function() {
                        return [];
                    }
                }
            });

            // Apply our new TrustManager
            var TrustManagers = [TrustManager.$new()];
            var SSLContextInit = SSLContext.getInstance('TLS');
            SSLContextInit.init(null, TrustManagers, null);

            // Override the default SSL socket factory
            var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
            HttpsURLConnection.setDefaultSSLSocketFactory.implementation = function(factory) {
                console.log('[+] Setting custom default SSL socket factory to trust all');
                HttpsURLConnection.setDefaultSSLSocketFactory.call(this, SSLContextInit.getSocketFactory());
            };

            console.log('[+] Custom X509TrustManager bypass applied');
        } catch (e) {
            console.log('[-] Custom X509TrustManager bypass not loaded:', e);
        }

        /**
         * 5. WebView SSL Error Bypass
         */
        try {
            var WebViewClient = Java.use('android.webkit.WebViewClient');
            WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
                console.log('[+] WebView SSL error intercepted, bypassing...');
                handler.proceed(); // Ignore the SSL error
            };
            console.log('[+] WebViewClient SSL bypass applied');
        } catch (e) {
            console.log('[-] WebView SSL bypass not loaded:', e);
        }

        /**
         * 6. Root Detection Bypass (common file checks)
         */
        try {
            var File = Java.use('java.io.File');
            File.exists.implementation = function() {
                var path = this.getAbsolutePath();
                // Common root binaries
                if (path.indexOf('su') > -1 ||
                    path.indexOf('magisk') > -1 ||
                    path.indexOf('Superuser.apk') > -1 ||
                    path.indexOf('xposed') > -1) {
                    console.log('[+] Bypassing root check for path: ' + path);
                    return false;
                }
                return this.exists.call(this);
            };
            console.log('[+] Root detection bypass (File.exists) applied');
        } catch (e) {
            console.log('[-] Root detection bypass not loaded:', e);
        }

        /**
         * 7. Anti-Debugging Bypass
         */
        try {
            // isDebuggerConnected -> return false
            var Debug = Java.use('android.os.Debug');
            Debug.isDebuggerConnected.implementation = function() {
                console.log('[+] isDebuggerConnected() called, returning false');
                return false;
            };
            console.log('[+] Anti-Debugging bypass applied');
        } catch (e) {
            console.log('[-] Anti-Debugging bypass not loaded:', e);
        }

        /**
         * 8. Network Security Config Bypass
         */
        try {
            var NetworkSecurityConfig = Java.use('android.security.net.config.NetworkSecurityConfig');
            NetworkSecurityConfig.isCleartextTrafficPermitted.implementation = function() {
                console.log('[+] Forcing isCleartextTrafficPermitted() -> true');
                return true;
            };
            console.log('[+] Network security config bypass applied');
        } catch (e) {
            console.log('[-] Network security config bypass not loaded:', e);
        }

        /**
         * 9. Basic Build/Tamper Checks
         *    If an app checks Build.FINGERPRINT or MODEL, etc.
         */
        try {
            var Build = Java.use('android.os.Build');
            
            // Example: override FINGERPRINT, MODEL, DEVICE, etc. to something generic
            Object.defineProperty(Build, 'FINGERPRINT', {
                get: function() {
                    console.log('[+] Build.FINGERPRINT check bypassed');
                    return 'generic/anyfingerprint';
                }
            });

            Object.defineProperty(Build, 'MODEL', {
                get: function() {
                    console.log('[+] Build.MODEL check bypassed');
                    return 'Pixel_5';
                }
            });

            console.log('[+] Basic build/tamper checks bypass applied');
        } catch (e) {
            console.log('[-] Build checks bypass not loaded:', e);
        }

        console.log('[*] Universal script completed all hooks.');
    });
}, 0);
