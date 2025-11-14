/**
 * Consent Agent - Handles cookie banner detection, consent management, and compliance checking
 */

import { BaseAgent } from '../core/BaseAgent.js';

export class ConsentAgent extends BaseAgent {
  constructor(options = {}) {
    super('consent', {
      priority: 10, // Run early
      dependencies: [],
      timeout: 10000,
      maxRetries: 2,
      version: '1.0.0',
      ...options
    });
  }

  /**
   * Execute consent analysis
   * @param {import('../core/ScanContext.js').ScanContext} context
   * @returns {Promise<import('../types/index.js').AgentResult>}
   */
  async execute(context) {
    const startTime = Date.now();
    const findings = [];
    const page = context.page;

    try {
      // 1. Detect cookie banner
      this.log('info', 'Detecting cookie banner');
      const bannerInfo = await this.detectCookieBanner(page);

      if (bannerInfo.present) {
        findings.push(
          this.createFinding({
            type: 'cookie_banner_detected',
            severity: 'info',
            message: `Cookie banner detected with ${bannerInfo.buttonCount} interactive elements`,
            evidence: {
              visible: bannerInfo.visible,
              hasAcceptButton: bannerInfo.hasAcceptButton,
              hasRejectButton: bannerInfo.hasRejectButton,
              hasSettingsButton: bannerInfo.hasSettingsButton,
              hasPrivacyLink: bannerInfo.hasPrivacyLink,
              position: bannerInfo.position,
              zIndex: bannerInfo.zIndex
            }
          })
        );

        // 2. Validate GDPR compliance
        const compliance = this.validateGDPRCompliance(bannerInfo);

        findings.push(
          this.createFinding({
            type: 'gdpr_compliance',
            severity: compliance.compliant ? 'info' : 'high',
            message: compliance.compliant
              ? 'Cookie banner appears GDPR compliant'
              : `GDPR compliance issues: ${compliance.issues.join(', ')}`,
            evidence: {
              compliant: compliance.compliant,
              issues: compliance.issues,
              requirements: {
                hasRejectOption: bannerInfo.hasRejectButton,
                hasPrivacyLink: bannerInfo.hasPrivacyLink,
                isVisible: bannerInfo.visible
              }
            }
          })
        );
      } else {
        findings.push(
          this.createFinding({
            type: 'cookie_banner_missing',
            severity: 'medium',
            message: 'No cookie consent banner detected',
            evidence: {
              checked: true,
              selectors: this.getBannerSelectors()
            }
          })
        );
      }

      // 3. Check TCF API availability
      this.log('info', 'Checking TCF API');
      const tcfInfo = await this.checkTCFAPI(page);

      if (tcfInfo.available) {
        findings.push(
          this.createFinding({
            type: 'tcf_api_detected',
            severity: 'info',
            message: 'IAB TCF API detected',
            evidence: {
              version: tcfInfo.version,
              gdprApplies: tcfInfo.gdprApplies,
              tcString: tcfInfo.tcString ? 'Present' : 'Not set',
              eventStatus: tcfInfo.eventStatus
            }
          })
        );
      }

      // 4. Analyze dataLayer for consent events
      this.log('info', 'Analyzing dataLayer consent events');
      const consentEvents = await this.analyzeConsentEvents(page);

      if (consentEvents.hasConsentMode) {
        findings.push(
          this.createFinding({
            type: 'consent_mode_detected',
            severity: 'info',
            message: 'Google Consent Mode detected',
            evidence: {
              defaultSet: consentEvents.hasDefaultConsent,
              updateFound: consentEvents.hasUpdateConsent,
              events: consentEvents.events.slice(0, 5)
            }
          })
        );
      }

      // 5. Mode-specific actions
      if (context.mode === 'accept') {
        findings.push(
          this.createFinding({
            type: 'consent_action_accept',
            severity: 'info',
            message: 'Consent accepted in this scan mode',
            evidence: { mode: 'accept' }
          })
        );
      } else if (context.mode === 'reject') {
        findings.push(
          this.createFinding({
            type: 'consent_action_reject',
            severity: 'info',
            message: 'Consent rejected in this scan mode',
            evidence: { mode: 'reject' }
          })
        );
      }

      const duration = Date.now() - startTime;
      return this.createSuccessResult(findings, {
        duration,
        startTime: new Date(startTime),
        endTime: new Date(),
        bannerDetected: bannerInfo.present,
        tcfAvailable: tcfInfo.available,
        consentModeDetected: consentEvents.hasConsentMode
      });
    } catch (error) {
      this.log('error', 'Consent agent execution failed', { error: error.message });
      return this.createFailureResult(error, findings, {
        duration: Date.now() - startTime,
        startTime: new Date(startTime),
        endTime: new Date()
      });
    }
  }

  /**
   * Detect cookie banner on page
   * @param {Object} page - Playwright page
   * @returns {Promise<Object>}
   */
  async detectCookieBanner(page) {
    return await page.evaluate(() => {
      const selectors = [
        '[class*="cookie"][class*="banner"]',
        '[class*="consent"]',
        '[id*="cookie"][id*="banner"]',
        '[id*="consent"]',
        '.cookie-notice',
        '#cookie-notice',
        '[role="dialog"][aria-label*="cookie" i]',
        '[role="dialog"][aria-label*="consent" i]',
        '#cookiescript_injected',
        '#CybotCookiebotDialog',
        '#onetrust-banner-sdk',
        '.cc-banner',
        '.cookie-consent',
        '.gdpr-banner'
      ];

      let banner = null;
      for (const sel of selectors) {
        const el = document.querySelector(sel);
        if (el && el.offsetParent !== null) {
          banner = el;
          break;
        }
      }

      if (!banner) {
        return { present: false };
      }

      const buttons = Array.from(
        banner.querySelectorAll('button, [role="button"], a[href], input[type="button"]')
      );

      const acceptBtn = buttons.find(b =>
        /accept|zustimmen|einverstanden|alle.*akzept|allow.*all|agree/i.test(b.textContent || '')
      );

      const rejectBtn = buttons.find(b =>
        /reject|ablehnen|nur.*notwendig|necessary.*only|decline|deny/i.test(b.textContent || '')
      );

      const settingsBtn = buttons.find(b =>
        /settings|einstellungen|customize|anpassen|preferences/i.test(b.textContent || '')
      );

      const privacyLink = banner.querySelector('a[href*="privacy"], a[href*="datenschutz"]');

      const styles = window.getComputedStyle(banner);

      return {
        present: true,
        visible: banner.offsetParent !== null,
        hasAcceptButton: !!acceptBtn,
        hasRejectButton: !!rejectBtn,
        hasSettingsButton: !!settingsBtn,
        hasPrivacyLink: !!privacyLink,
        buttonCount: buttons.length,
        position: styles.position,
        zIndex: styles.zIndex,
        bannerClass: banner.className,
        bannerId: banner.id
      };
    });
  }

  /**
   * Validate GDPR compliance
   * @param {Object} bannerInfo - Banner information
   * @returns {Object}
   */
  validateGDPRCompliance(bannerInfo) {
    const issues = [];

    if (!bannerInfo.present) {
      issues.push('No consent banner found');
    }

    if (bannerInfo.present && !bannerInfo.hasRejectButton) {
      issues.push('No reject/decline option available');
    }

    if (bannerInfo.present && !bannerInfo.hasAcceptButton) {
      issues.push('No accept option available');
    }

    if (bannerInfo.present && !bannerInfo.hasPrivacyLink) {
      issues.push('No link to privacy policy');
    }

    if (bannerInfo.present && !bannerInfo.visible) {
      issues.push('Banner not visible to users');
    }

    return {
      compliant: issues.length === 0,
      issues
    };
  }

  /**
   * Check for TCF (Transparency & Consent Framework) API
   * @param {Object} page - Playwright page
   * @returns {Promise<Object>}
   */
  async checkTCFAPI(page) {
    return await page.evaluate(async () => {
      const result = {
        available: false,
        version: null,
        gdprApplies: null,
        tcString: null,
        eventStatus: null
      };

      if (typeof window.__tcfapi === 'function') {
        result.available = true;

        try {
          await new Promise((resolve) => {
            window.__tcfapi('addEventListener', 2, (tcData, success) => {
              if (success && tcData) {
                result.version = 2;
                result.gdprApplies = tcData.gdprApplies;
                result.tcString = tcData.tcString;
                result.eventStatus = tcData.eventStatus;
              }
              resolve();
            });

            // Timeout after 2 seconds
            setTimeout(resolve, 2000);
          });
        } catch (e) {
          console.error('TCF API check failed:', e);
        }
      }

      return result;
    });
  }

  /**
   * Analyze dataLayer for consent events
   * @param {Object} page - Playwright page
   * @returns {Promise<Object>}
   */
  async analyzeConsentEvents(page) {
    return await page.evaluate(() => {
      const result = {
        hasConsentMode: false,
        hasDefaultConsent: false,
        hasUpdateConsent: false,
        events: []
      };

      if (!Array.isArray(window.dataLayer)) {
        return result;
      }

      for (const item of window.dataLayer) {
        if (!item || typeof item !== 'object') continue;

        // Check for consent mode events
        if (item[0] === 'consent' || item.event === 'consent') {
          result.hasConsentMode = true;

          if (item[1] === 'default' || item.type === 'default') {
            result.hasDefaultConsent = true;
          }

          if (item[1] === 'update' || item.type === 'update') {
            result.hasUpdateConsent = true;
          }

          result.events.push({
            type: item[1] || item.type || 'unknown',
            data: item[2] || item.data || {}
          });
        }

        // Check for other consent-related events
        if (typeof item.event === 'string' && /consent|cookie|gdpr|privacy/i.test(item.event)) {
          result.events.push({
            event: item.event,
            data: item
          });
        }
      }

      return result;
    });
  }

  /**
   * Get banner selectors for evidence
   * @returns {Array<string>}
   */
  getBannerSelectors() {
    return [
      '[class*="cookie"][class*="banner"]',
      '[class*="consent"]',
      '[id*="cookie"]',
      '[id*="consent"]',
      '[role="dialog"]',
      '.cookie-notice',
      '#onetrust-banner-sdk',
      '#CybotCookiebotDialog'
    ];
  }

  /**
   * Get current session identifier
   * @returns {string}
   */
  getCurrentSession() {
    return 'consent-scan';
  }
}
