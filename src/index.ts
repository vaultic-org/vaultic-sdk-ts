// Vaultic SDK - Main exports
// All exports are designed to require server validation

export { VaulticClient } from './vaultic-client';

export type {
  // Types
  VaulticConfig,
  Status,
  Registration,
  VerificationMethod,
  EncryptionOptions,
  DecryptionOptions,
  StatusChangeEvent,
  ProgressEvent,
  Device,
  Group,
  Identity,
  Challenge,
  AuthenticationToken,
  Resource,
  StreamEncryptionOptions,
  EncryptionSession,
  SharingOptions,
  VerificationKey,
  ResourceMetadata,
  EncryptionFormat,
  EncryptionStream,
  DecryptionStream,
  ProvisionalMember
} from './types';

export {
  CryptoAlgorithm
} from './types';

export {
  // Error classes
  VaulticError,
  ApiConnectionRequiredError,
  ServerValidationRequiredError,
  InvalidServerSignatureError,
  AuthenticationRequiredError,
  DeviceNotRegisteredError,
  GroupNotFoundError,
  ResourceNotFoundError,
  QuotaExceededError,
  InvalidApiKeyError,
  ChallengeExpiredError,
  ForkDetectedError,
  
  // Error codes
  ErrorCodes
} from './errors';

/**
 * IMPORTANT USAGE NOTICE:
 * 
 * This SDK is designed to be COMPLETELY DEPENDENT on the Vaultic API.
 * 
 * ⚠️  NO OFFLINE FUNCTIONALITY: All operations require active API connection
 * ⚠️  SERVER-SIDE VALIDATION: All IDs, tokens, and operations validated by server
 * ⚠️  NATIVE CRYPTO ONLY: All cryptographic operations use native WebCrypto APIs only
 * 
 * Usage Example:
 * ```typescript
 * import { VaulticClient } from '@vaultic/sdk';
 * 
 * const vaultic = new VaulticClient({
 *   appId: 'your-app',
 *   apiKey: 'vlt_your_api_key' // Must be valid Vaultic API key
 * });
 * 
 * // MANDATORY: Initialize with API validation
 * await vaultic.initialize();
 * 
 * // ALL operations require server approval
 * await vaultic.start(userId);
 * await vaultic.registerIdentity({ passphrase: 'user-passphrase' });
 * 
 * // Encryption requires server quota validation
 * const encrypted = await vaultic.encrypt('Hello World');
 * const decrypted = await vaultic.decrypt(encrypted);
 * ```
 * 
 * Security Architecture:
 * - Device IDs generated server-side only
 * - All resource IDs created by API Vaultic  
 * - Group management server-controlled
 * - Quota enforcement server-side
 * - Authentication via server challenges
 * - Local storage encrypted with server signatures
 * - All cryptographic operations use native WebCrypto APIs only
 * 
 * If this SDK is forked, the fork will be NON-FUNCTIONAL because:
 * - No valid API keys can be generated locally
 * - Server signatures cannot be forged
 * - All critical operations fail without API connection
 * - Resource/device/group IDs are server-generated only
 * - No custom cryptographic engines are supported
 */
