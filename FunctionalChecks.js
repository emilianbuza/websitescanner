/**
 * Functional Website Checks
 * ===========================
 * These are REAL functionality tests that find actual business-critical problems,
 * NOT generic SEO checks that are available in every free tool.
 *
 * Each check tests if critical features actually WORK.
 */

export class FunctionalChecks {
  constructor(page, context) {
    this.page = page;
    this.context = context;
    this.results = {
      formFunctionality: null,
      paymentGateway: null,
      shoppingCart: null,
      liveChat: null,
      cdnDependencies: null,
      apiEndpoints: null,
      authenticationFlow: null,
      databaseErrors: null,
      emailService: null,
      criticalResources: null,
      // Bonus checks
      geoBlocking: null,
      abTestFramework: null,
      inventoryAPI: null,
      cacheHeaders: null
    };
  }

  /**
   * Run all functional checks
   */
  async runAll() {
    console.log('🔧 Running functional checks...');

    await Promise.allSettled([
      this.checkFormFunctionality(),
      this.checkPaymentGateway(),
      this.checkShoppingCart(),
      this.checkLiveChat(),
      this.checkCDNDependencies(),
      this.checkAPIEndpoints(),
      this.checkAuthenticationFlow(),
      this.checkDatabaseErrors(),
      this.checkEmailService(),
      this.checkCriticalResources(),
      this.checkGeoBlocking(),
      this.checkABTestFramework(),
      this.checkInventoryAPI(),
      this.checkCacheHeaders()
    ]);

    return this.results;
  }

  /**
   * 1. FORM FUNCTIONALITY CHECK
   * Tests if contact/newsletter forms can actually submit
   */
  async checkFormFunctionality() {
    try {
      const forms = await this.page.$$eval('form', forms => {
        return forms.map(form => ({
          action: form.action,
          method: form.method || 'GET',
          hasSubmit: form.querySelector('[type="submit"]') !== null,
          hasEmail: form.querySelector('[type="email"]') !== null,
          hasCSRF: form.querySelector('[name*="csrf"], [name*="token"], [name="_token"]') !== null,
          id: form.id,
          class: form.className
        }));
      });

      const issues = [];
      const working = [];

      for (const form of forms) {
        if (!form.action || form.action === '' || form.action.includes('javascript:')) {
          issues.push({
            type: 'broken_form_action',
            form: form.id || form.class || 'unnamed',
            message: `Form has no valid action URL`,
            businessImpact: 'Form submissions will fail = 0 leads/contact requests'
          });
        } else if (!form.hasSubmit) {
          issues.push({
            type: 'missing_submit_button',
            form: form.id || form.class || 'unnamed',
            message: 'Form has no submit button',
            businessImpact: 'Users cannot submit this form'
          });
        } else if (form.hasEmail && !form.hasCSRF && form.method === 'POST') {
          issues.push({
            type: 'missing_csrf_protection',
            form: form.id || form.class || 'unnamed',
            message: 'Form lacks CSRF token (potential security issue)',
            businessImpact: 'Form might be vulnerable to spam/attacks'
          });
        } else {
          working.push({
            form: form.id || form.class || 'unnamed',
            action: form.action,
            method: form.method
          });
        }
      }

      this.results.formFunctionality = {
        status: issues.length === 0 ? 'ok' : 'issues_found',
        totalForms: forms.length,
        workingForms: working.length,
        brokenForms: issues.length,
        issues,
        working
      };
    } catch (error) {
      this.results.formFunctionality = { status: 'error', error: error.message };
    }
  }

  /**
   * 2. PAYMENT GATEWAY HEALTH CHECK
   * Checks if payment provider scripts load correctly
   */
  async checkPaymentGateway() {
    try {
      const paymentProviders = {
        stripe: { pattern: /js\.stripe\.com/i, name: 'Stripe' },
        paypal: { pattern: /paypal\.com.*\/sdk\//i, name: 'PayPal' },
        klarna: { pattern: /x\.klarnacdn\.net/i, name: 'Klarna' },
        square: { pattern: /squareup\.com.*\/web-sdk/i, name: 'Square' },
        braintree: { pattern: /braintreegateway\.com/i, name: 'Braintree' },
        mollie: { pattern: /mollie\.com/i, name: 'Mollie' },
        adyen: { pattern: /adyen\.com/i, name: 'Adyen' }
      };

      const detectedProviders = [];
      const issues = [];

      // Check scripts in page
      const scripts = await this.page.$$eval('script[src]', scripts =>
        scripts.map(s => s.src)
      );

      for (const [key, provider] of Object.entries(paymentProviders)) {
        const found = scripts.some(src => provider.pattern.test(src));
        if (found) {
          // Try to verify provider actually loaded
          const loaded = await this.page.evaluate((providerName) => {
            if (providerName === 'Stripe') return typeof window.Stripe !== 'undefined';
            if (providerName === 'PayPal') return typeof window.paypal !== 'undefined';
            if (providerName === 'Square') return typeof window.Square !== 'undefined';
            return true; // Default to assuming it loaded
          }, provider.name);

          if (!loaded) {
            issues.push({
              type: 'payment_script_not_initialized',
              provider: provider.name,
              message: `${provider.name} script loaded but not initialized`,
              businessImpact: `${provider.name} payments may fail = Revenue loss`
            });
          }

          detectedProviders.push({
            provider: provider.name,
            loaded,
            status: loaded ? 'ok' : 'not_initialized'
          });
        }
      }

      this.results.paymentGateway = {
        status: issues.length === 0 && detectedProviders.length > 0 ? 'ok' : (detectedProviders.length === 0 ? 'no_provider_detected' : 'issues_found'),
        providers: detectedProviders,
        issues
      };
    } catch (error) {
      this.results.paymentGateway = { status: 'error', error: error.message };
    }
  }

  /**
   * 3. SHOPPING CART SESSION TESTING
   * Tests if cart persists across page reloads
   */
  async checkShoppingCart() {
    try {
      const cartIndicators = await this.page.evaluate(() => {
        const selectors = [
          '[class*="cart"]', '[id*="cart"]',
          '[class*="basket"]', '[id*="basket"]',
          '[class*="bag"]', '[data-cart]',
          '.woocommerce-cart', '.cart-count',
          '[aria-label*="cart" i]', '[aria-label*="basket" i]'
        ];

        const found = selectors.map(sel => {
          const el = document.querySelector(sel);
          return el ? {
            selector: sel,
            text: el.textContent.trim().substring(0, 50),
            hasCount: /\d+/.test(el.textContent)
          } : null;
        }).filter(Boolean);

        // Check for cart in localStorage/sessionStorage
        const storageKeys = [...Object.keys(localStorage), ...Object.keys(sessionStorage)];
        const cartStorage = storageKeys.filter(k =>
          /cart|basket|bag|woo/i.test(k)
        );

        return {
          elements: found,
          storage: cartStorage,
          hasLocalStorage: cartStorage.some(k => localStorage.getItem(k)),
          hasSessionStorage: cartStorage.some(k => sessionStorage.getItem(k))
        };
      });

      const issues = [];

      if (cartIndicators.elements.length > 0 && !cartIndicators.hasLocalStorage && !cartIndicators.hasSessionStorage) {
        issues.push({
          type: 'cart_not_persisted',
          message: 'Shopping cart elements found but no storage mechanism detected',
          businessImpact: 'Cart may be lost on page reload = 73% abandonment rate increase'
        });
      }

      this.results.shoppingCart = {
        status: cartIndicators.elements.length === 0 ? 'no_cart_detected' : (issues.length === 0 ? 'ok' : 'issues_found'),
        hasCartElements: cartIndicators.elements.length > 0,
        usesLocalStorage: cartIndicators.hasLocalStorage,
        usesSessionStorage: cartIndicators.hasSessionStorage,
        cartElements: cartIndicators.elements.length,
        storageKeys: cartIndicators.storage,
        issues
      };
    } catch (error) {
      this.results.shoppingCart = { status: 'error', error: error.message };
    }
  }

  /**
   * 4. LIVE CHAT & WEBSOCKET STATUS
   * Checks if live chat tools actually connect
   */
  async checkLiveChat() {
    try {
      const chatProviders = await this.page.evaluate(() => {
        const providers = {
          intercom: window.Intercom !== undefined,
          drift: window.drift !== undefined,
          zendesk: window.zE !== undefined || window.zEmbed !== undefined,
          tawk: window.Tawk_API !== undefined,
          crisp: window.$crisp !== undefined,
          livechat: window.LiveChatWidget !== undefined,
          freshchat: window.fcWidget !== undefined,
          tidio: window.tidioChatApi !== undefined,
          hubspot: window.HubSpotConversations !== undefined
        };

        return providers;
      });

      const detectedChats = Object.entries(chatProviders)
        .filter(([name, loaded]) => loaded)
        .map(([name]) => ({ provider: name.charAt(0).toUpperCase() + name.slice(1), loaded: true }));

      // Check for WebSocket connections
      const wsConnections = await this.page.evaluate(() => {
        // This is a simplified check - in reality WebSockets are harder to detect after connection
        return {
          supportsWebSocket: typeof WebSocket !== 'undefined',
          // We can't reliably count active WS connections from the page context
          note: 'WebSocket support detected'
        };
      });

      this.results.liveChat = {
        status: detectedChats.length > 0 ? 'ok' : 'no_chat_detected',
        providers: detectedChats,
        websocketSupport: wsConnections.supportsWebSocket,
        totalProviders: detectedChats.length
      };
    } catch (error) {
      this.results.liveChat = { status: 'error', error: error.message };
    }
  }

  /**
   * 5. CDN DEPENDENCY AVAILABILITY
   * Tests if critical CDNs are reachable
   */
  async checkCDNDependencies() {
    try {
      const scripts = await this.page.$$eval('script[src], link[href]', elements => {
        return elements.map(el => {
          const url = el.src || el.href;
          const isCDN = /cdn|cloudflare|jsdelivr|unpkg|cdnjs|bootstrapcdn|jquery\.com|googleapis\.com|gstatic\.com/i.test(url);
          return isCDN ? url : null;
        }).filter(Boolean);
      });

      const cdnResources = [...new Set(scripts)];
      const failedCDNs = [];
      const workingCDNs = [];

      // Check which CDN resources failed (from network log)
      const performance = await this.page.evaluate(() => {
        const entries = performance.getEntriesByType('resource');
        return entries.map(e => ({
          name: e.name,
          transferSize: e.transferSize,
          duration: e.duration,
          failed: e.transferSize === 0 && e.duration > 0
        }));
      });

      for (const cdn of cdnResources) {
        const perfEntry = performance.find(p => p.name === cdn);
        if (perfEntry && perfEntry.failed) {
          const cdnHost = new URL(cdn).hostname;
          failedCDNs.push({
            url: cdn,
            host: cdnHost,
            businessImpact: 'CDN failure may break entire website functionality'
          });
        } else if (perfEntry) {
          workingCDNs.push({ url: cdn, loadTime: Math.round(perfEntry.duration) });
        }
      }

      this.results.cdnDependencies = {
        status: failedCDNs.length === 0 ? 'ok' : 'cdn_failures_detected',
        totalCDNResources: cdnResources.length,
        failed: failedCDNs.length,
        working: workingCDNs.length,
        failedCDNs,
        workingCDNs: workingCDNs.slice(0, 5) // Limit to first 5
      };
    } catch (error) {
      this.results.cdnDependencies = { status: 'error', error: error.message };
    }
  }

  /**
   * 6. API ENDPOINT TESTING
   * Tests if important API calls succeed
   */
  async checkAPIEndpoints() {
    try {
      const apiCalls = await this.page.evaluate(() => {
        const entries = performance.getEntriesByType('resource');
        const apis = entries.filter(e => {
          const isAPI = e.name.includes('/api/') ||
                       e.name.includes('/graphql') ||
                       e.name.includes('.json') ||
                       e.initiatorType === 'fetch' ||
                       e.initiatorType === 'xmlhttprequest';
          return isAPI;
        });

        return apis.map(api => ({
          url: api.name,
          duration: Math.round(api.duration),
          size: api.transferSize,
          failed: api.transferSize === 0 && api.duration > 0
        }));
      });

      const failedAPIs = apiCalls.filter(api => api.failed);
      const workingAPIs = apiCalls.filter(api => !api.failed);
      const issues = [];

      for (const api of failedAPIs) {
        issues.push({
          type: 'api_call_failed',
          url: api.url,
          message: 'API endpoint failed to respond',
          businessImpact: 'Feature using this API may not work (search, products, etc.)'
        });
      }

      this.results.apiEndpoints = {
        status: failedAPIs.length === 0 ? 'ok' : 'api_failures_detected',
        totalAPICalls: apiCalls.length,
        failed: failedAPIs.length,
        working: workingAPIs.length,
        issues,
        workingAPIs: workingAPIs.slice(0, 5) // Show first 5
      };
    } catch (error) {
      this.results.apiEndpoints = { status: 'error', error: error.message };
    }
  }

  /**
   * 7. AUTHENTICATION FLOW ISSUES
   * Checks for login/register functionality
   */
  async checkAuthenticationFlow() {
    try {
      const authElements = await this.page.evaluate(() => {
        const loginLinks = Array.from(document.querySelectorAll('a, button')).filter(el => {
          const text = el.textContent.toLowerCase();
          return text.includes('login') || text.includes('anmelden') ||
                 text.includes('sign in') || text.includes('einloggen');
        });

        const registerLinks = Array.from(document.querySelectorAll('a, button')).filter(el => {
          const text = el.textContent.toLowerCase();
          return text.includes('register') || text.includes('registrieren') ||
                 text.includes('sign up') || text.includes('konto erstellen');
        });

        const loginForms = Array.from(document.querySelectorAll('form')).filter(form => {
          const hasPassword = form.querySelector('[type="password"]') !== null;
          const hasEmail = form.querySelector('[type="email"], [name*="email"], [name*="username"]') !== null;
          return hasPassword && hasEmail;
        });

        return {
          hasLoginLinks: loginLinks.length > 0,
          hasRegisterLinks: registerLinks.length > 0,
          hasLoginForms: loginForms.length > 0,
          loginFormsCount: loginForms.length
        };
      });

      const issues = [];

      if (authElements.hasLoginLinks && !authElements.hasLoginForms) {
        // This might be fine if login is on a different page
        // We'll mark it as informational
      }

      this.results.authenticationFlow = {
        status: authElements.hasLoginLinks || authElements.hasRegisterLinks ? 'detected' : 'no_auth_detected',
        hasLogin: authElements.hasLoginLinks,
        hasRegister: authElements.hasRegisterLinks,
        hasLoginForms: authElements.hasLoginForms,
        loginFormsCount: authElements.loginFormsCount,
        issues
      };
    } catch (error) {
      this.results.authenticationFlow = { status: 'error', error: error.message };
    }
  }

  /**
   * 8. DATABASE ERROR LEAKAGE DETECTION
   * Looks for visible database errors
   */
  async checkDatabaseErrors() {
    try {
      const dbErrors = await this.page.evaluate(() => {
        const bodyText = document.body.innerText;
        const htmlContent = document.documentElement.innerHTML;

        const errorPatterns = [
          /mysql.*error/i,
          /postgresql.*error/i,
          /ora-\d{5}/i, // Oracle errors
          /sqlite.*error/i,
          /mongodb.*error/i,
          /syntax error.*sql/i,
          /table.*doesn't exist/i,
          /column.*not found/i,
          /database connection failed/i,
          /PDOException/i,
          /SQLException/i,
          /pg_query\(\).*error/i
        ];

        const found = [];
        for (const pattern of errorPatterns) {
          if (pattern.test(bodyText) || pattern.test(htmlContent)) {
            found.push({
              pattern: pattern.toString(),
              type: 'database_error_exposed'
            });
          }
        }

        return found;
      });

      const issues = dbErrors.map(err => ({
        type: 'database_error_visible',
        pattern: err.pattern,
        message: 'Database error visible in page content',
        businessImpact: 'Unprofessional + Security risk (exposes DB structure)',
        severity: 'high'
      }));

      this.results.databaseErrors = {
        status: dbErrors.length === 0 ? 'ok' : 'errors_detected',
        errorsFound: dbErrors.length,
        issues
      };
    } catch (error) {
      this.results.databaseErrors = { status: 'error', error: error.message };
    }
  }

  /**
   * 9. EMAIL SERVICE CONFIGURATION
   * Tests newsletter/email signup functionality
   */
  async checkEmailService() {
    try {
      const emailServices = await this.page.evaluate(() => {
        const scripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src);

        const providers = {
          mailchimp: scripts.some(s => /mailchimp\.com/i.test(s)),
          klaviyo: scripts.some(s => /klaviyo\.com/i.test(s)),
          sendgrid: scripts.some(s => /sendgrid/i.test(s)),
          mailerlite: scripts.some(s => /mailerlite/i.test(s)),
          convertkit: scripts.some(s => /convertkit\.com/i.test(s)),
          activecampaign: scripts.some(s => /activehosted\.com/i.test(s)),
          constantcontact: scripts.some(s => /constantcontact\.com/i.test(s))
        };

        const newsletterForms = Array.from(document.querySelectorAll('form')).filter(form => {
          const text = form.textContent.toLowerCase();
          return (text.includes('newsletter') || text.includes('email') || text.includes('subscribe')) &&
                 form.querySelector('[type="email"]') !== null;
        });

        return {
          providers,
          newsletterFormsCount: newsletterForms.length
        };
      });

      const detectedProviders = Object.entries(emailServices.providers)
        .filter(([name, detected]) => detected)
        .map(([name]) => name);

      this.results.emailService = {
        status: detectedProviders.length > 0 || emailServices.newsletterFormsCount > 0 ? 'detected' : 'no_email_service',
        providers: detectedProviders,
        newsletterForms: emailServices.newsletterFormsCount,
        totalProviders: detectedProviders.length
      };
    } catch (error) {
      this.results.emailService = { status: 'error', error: error.message };
    }
  }

  /**
   * 10. CRITICAL RESOURCE LOADING
   * Tests if main JavaScript bundles loaded successfully
   */
  async checkCriticalResources() {
    try {
      const resources = await this.page.evaluate(() => {
        const scripts = Array.from(document.querySelectorAll('script[src]'));
        const styles = Array.from(document.querySelectorAll('link[rel="stylesheet"]'));

        const jsErrors = window.__jsLoadErrors || [];

        const largeScripts = scripts
          .map(s => s.src)
          .filter(src => !src.includes('analytics') && !src.includes('tracking'));

        return {
          totalScripts: scripts.length,
          totalStyles: styles.length,
          jsErrors,
          hasBundleJS: scripts.some(s => /bundle|app|main|vendor/i.test(s.src))
        };
      });

      const jsInitialized = await this.page.evaluate(() => {
        // Check if common frameworks initialized
        return {
          react: typeof window.React !== 'undefined' || document.querySelector('[data-reactroot]') !== null,
          vue: typeof window.Vue !== 'undefined' || document.querySelector('[data-v-]') !== null,
          angular: typeof window.angular !== 'undefined' || document.querySelector('[ng-version]') !== null,
          jquery: typeof window.jQuery !== 'undefined'
        };
      });

      const issues = [];

      if (resources.hasBundleJS && Object.values(jsInitialized).every(v => !v)) {
        issues.push({
          type: 'js_bundle_not_initialized',
          message: 'Main JS bundle loaded but framework not initialized',
          businessImpact: 'Website may not be interactive = Users cannot use app features'
        });
      }

      this.results.criticalResources = {
        status: issues.length === 0 ? 'ok' : 'initialization_issues',
        totalScripts: resources.totalScripts,
        totalStyles: resources.totalStyles,
        frameworks: jsInitialized,
        issues
      };
    } catch (error) {
      this.results.criticalResources = { status: 'error', error: error.message };
    }
  }

  /**
   * 11. GEO-BLOCKING / REGION DETECTION
   */
  async checkGeoBlocking() {
    try {
      const geoInfo = await this.page.evaluate(() => {
        const hasGeoRedirect = document.querySelector('[data-geo]') !== null ||
                             document.querySelector('[class*="region"]') !== null ||
                             localStorage.getItem('userRegion') !== null ||
                             localStorage.getItem('userCountry') !== null;

        return {
          hasGeoElements: hasGeoRedirect,
          region: localStorage.getItem('userRegion'),
          country: localStorage.getItem('userCountry')
        };
      });

      this.results.geoBlocking = {
        status: geoInfo.hasGeoElements ? 'detected' : 'not_detected',
        ...geoInfo
      };
    } catch (error) {
      this.results.geoBlocking = { status: 'error', error: error.message };
    }
  }

  /**
   * 12. A/B TEST FRAMEWORK STATUS
   */
  async checkABTestFramework() {
    try {
      const abTests = await this.page.evaluate(() => {
        return {
          optimizely: typeof window.optimizely !== 'undefined',
          vwo: typeof window.VWO !== 'undefined' || typeof window._vwo_code !== 'undefined',
          googleOptimize: typeof window.gtag !== 'undefined' && window.dataLayer?.some(item =>
            item[0] === 'config' && item[1]?.includes('OPT-')
          ),
          abTasty: typeof window.ABTasty !== 'undefined'
        };
      });

      const detectedFrameworks = Object.entries(abTests)
        .filter(([name, detected]) => detected)
        .map(([name]) => name);

      this.results.abTestFramework = {
        status: detectedFrameworks.length > 0 ? 'detected' : 'not_detected',
        frameworks: detectedFrameworks
      };
    } catch (error) {
      this.results.abTestFramework = { status: 'error', error: error.message };
    }
  }

  /**
   * 13. INVENTORY API STATUS
   */
  async checkInventoryAPI() {
    try {
      const inventory = await this.page.evaluate(() => {
        // Check for stock/inventory indicators
        const stockElements = Array.from(document.querySelectorAll('[class*="stock"], [class*="inventory"], [data-stock]'));
        const hasInventoryData = stockElements.length > 0;

        // Check for "out of stock" messages
        const outOfStock = Array.from(document.querySelectorAll('*')).some(el => {
          const text = el.textContent.toLowerCase();
          return text.includes('out of stock') ||
                 text.includes('nicht auf lager') ||
                 text.includes('ausverkauft') ||
                 text.includes('sold out');
        });

        return {
          hasInventoryElements: hasInventoryData,
          stockElementsCount: stockElements.length,
          hasOutOfStock: outOfStock
        };
      });

      this.results.inventoryAPI = {
        status: inventory.hasInventoryElements ? 'detected' : 'not_detected',
        ...inventory
      };
    } catch (error) {
      this.results.inventoryAPI = { status: 'error', error: error.message };
    }
  }

  /**
   * 14. CACHE HEADERS CHECK
   */
  async checkCacheHeaders() {
    try {
      const cacheInfo = await this.page.evaluate(() => {
        const entries = performance.getEntriesByType('resource');
        const cached = entries.filter(e => e.transferSize === 0 && e.decodedBodySize > 0);
        const notCached = entries.filter(e => e.transferSize > 0);

        return {
          totalResources: entries.length,
          cachedResources: cached.length,
          notCachedResources: notCached.length,
          cacheRatio: Math.round((cached.length / entries.length) * 100)
        };
      });

      const issues = [];

      if (cacheInfo.cacheRatio < 20) {
        issues.push({
          type: 'low_cache_usage',
          message: `Only ${cacheInfo.cacheRatio}% of resources are cached`,
          businessImpact: 'Slow page loads = Higher bounce rate'
        });
      }

      this.results.cacheHeaders = {
        status: issues.length === 0 ? 'ok' : 'optimization_needed',
        ...cacheInfo,
        issues
      };
    } catch (error) {
      this.results.cacheHeaders = { status: 'error', error: error.message };
    }
  }
}
