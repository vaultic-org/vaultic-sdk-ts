// VaulticClient - Main SDK class
// CRITICAL: ALL operations require server validation - no offline functionality

import { EventEmitter } from 'events';
import {
    VaulticConfig,
    Status,
    Registration,
    VerificationMethod,
    EncryptionOptions,
    DecryptionOptions,
    StatusChangeEvent,
    Identity,
    LocalData,
    DeviceKeys,
    StreamEncryptionOptions,
    EncryptionSession,
    SharingOptions,
    VerificationKey,
    Device
} from './types';
import {
    ApiConnectionRequiredError,
    DeviceNotRegisteredError,
    ServerValidationRequiredError,
    throwIfOffline
} from './errors';
import { ApiClient } from './client/api-client';
import { KeyStore } from './storage/key-store';
import { CRYPTO_PARAMS, secureWipe } from './config/security';
import { InputValidator } from './validation/input-validator';

export class VaulticClient extends EventEmitter {
    private config: VaulticConfig;
    private apiClient: ApiClient;
    private keyStore: KeyStore;
    private status: Status = Status.STOPPED;
    private currentUserId: string | null = null;
    private userSecret: Uint8Array | null = null;
    private deviceKeys: DeviceKeys | null = null;

    constructor(config: VaulticConfig) {
        super();
        
        // Validate configuration first
        InputValidator.validateConfig(config);
        
        // Use validated config
        this.config = config;
        this.apiClient = new ApiClient(this.config);
        this.keyStore = new KeyStore();
    }

    /**
     * Initialize the SDK - REQUIRES API connection
     * This is the ONLY way to start the SDK - no offline mode exists
     */
    async initialize(): Promise<void> {
        try {
            this.setStatus(Status.STARTING);

            // MANDATORY: Validate API connection first
            await this.apiClient.initialize();

            // Check if we have local keys (but they're worthless without server validation)
            const hasLocalKeys = await this.keyStore.hasKeys();

            if (hasLocalKeys) {
                // Local keys exist but MUST be validated with server
                const lastSync = await this.keyStore.getLastSync();
                const oneHourAgo = Date.now() - (60 * 60 * 1000);

                if (!lastSync || lastSync < oneHourAgo) {
                    console.warn(
                        '[VAULTIC SDK] Local keys found but not recently validated. ' +
                        'Server re-authentication required for security.'
                    );
                    this.setStatus(Status.IDENTITY_VERIFICATION_NEEDED);
                } else {
                    this.setStatus(Status.IDENTITY_VERIFICATION_NEEDED);
                }
            } else {
                this.setStatus(Status.IDENTITY_REGISTRATION_NEEDED);
            }
        } catch (error) {
            this.setStatus(Status.STOPPED);
            throw new ApiConnectionRequiredError('initialize');
        }
    }

    /**
     * Start session for user - REQUIRES server authentication
     * No local session management - everything goes through API
     */
    async start(userId: string): Promise<void> {
        // Validate user ID first
        const validUserId = InputValidator.validateUserId(userId);
        
        throwIfOffline('start', this.apiClient.isAuthenticated);

        this.currentUserId = validUserId;

        // Try to load local keys (but server validation is still required)
        if (this.userSecret) {
            const localData = await this.keyStore.load(this.userSecret);
            if (localData?.deviceKeys) {
                this.deviceKeys = localData.deviceKeys;

                // Even with local keys, we MUST authenticate with server
                await this.authenticateWithServer();
            }
        }

        // Update status based on what server says about this user
        try {
            const identity = await this.apiClient.getIdentity(userId);

            if (identity.devices.length === 0) {
                this.setStatus(Status.IDENTITY_REGISTRATION_NEEDED);
            } else if (!this.deviceKeys) {
                this.setStatus(Status.IDENTITY_VERIFICATION_NEEDED);
            } else {
                this.setStatus(Status.READY);
            }
        } catch (error) {
            throw new ServerValidationRequiredError('user_identity');
        }
    }

    /**
     * Register identity - REQUIRES server-generated device ID
     * No local identity creation - server controls all identities
     */
    async registerIdentity(registration: Registration): Promise<Identity> {
        // Validate registration data
        const validRegistration = InputValidator.validateRegistration(registration);
        
        throwIfOffline('registerIdentity', this.apiClient.isAuthenticated);

        if (this.status !== Status.IDENTITY_REGISTRATION_NEEDED) {
            throw new Error('Identity registration not needed in current status');
        }

        if (!this.currentUserId) {
            throw new Error('No user ID set. Call start() first.');
        }

        try {
            // Generate local device keys (private keys stay local)
            this.deviceKeys = await this.generateDeviceKeys();

            // Extract public keys for server registration
            const publicKeys = await this.extractPublicKeys(this.deviceKeys);

            // CRITICAL: Register device with server - device ID comes from server ONLY
            const device = await this.apiClient.registerDevice(publicKeys);

            // Generate user secret from passphrase (if provided)
            if (validRegistration.passphrase) {
                this.userSecret = await this.deriveUserSecret(validRegistration.passphrase);
            } else {
                this.userSecret = crypto.getRandomValues(new Uint8Array(64));
            }

            // Save local data with SERVER signature
            const localData: LocalData = {
                deviceKeys: this.deviceKeys,
                userSecret: this.userSecret,
                lastSyncTimestamp: Date.now(),
                serverSignature: device.serverSignature // REQUIRED server signature
            };

            await this.keyStore.save(localData, this.userSecret);

            // Authenticate with server
            await this.authenticateWithServer();

            // Get updated identity from server
            const identity = await this.apiClient.getIdentity(this.currentUserId);

            this.setStatus(Status.READY);
            return identity;
        } catch (error) {
            throw new ServerValidationRequiredError('identity_registration');
        }
    }

    /**
     * Verify identity with existing device - REQUIRES server validation
     * No local verification - server must validate all identity operations
     */
    async verifyIdentity(verification: VerificationMethod): Promise<void> {
        // Validate verification method
        const validVerification = InputValidator.validateVerificationMethod(verification);
        
        throwIfOffline('verifyIdentity', this.apiClient.isAuthenticated);

        if (this.status !== Status.IDENTITY_VERIFICATION_NEEDED) {
            throw new Error('Identity verification not needed in current status');
        }

        if (!this.currentUserId) {
            throw new Error('No user ID set. Call start() first.');
        }

        try {
            // Derive user secret from verification method
            if (validVerification.type === 'passphrase' && validVerification.value) {
                this.userSecret = await this.deriveUserSecret(validVerification.value);
            } else {
                throw new Error('Unsupported verification method');
            }

            // Try to load local keys with the user secret
            const localData = await this.keyStore.load(this.userSecret);
            if (!localData?.deviceKeys) {
                throw new Error('No valid device keys found for this verification');
            }

            this.deviceKeys = localData.deviceKeys;

            // MANDATORY: Authenticate with server even with local keys
            await this.authenticateWithServer();

            this.setStatus(Status.READY);
        } catch (error) {
            throw new ServerValidationRequiredError('identity_verification');
        }
    }

    /**
     * Encrypt data - REQUIRES server validation for quota and permissions
     * All encryption operations must be pre-approved by server
     */
    async encrypt(data: string | Uint8Array, options: EncryptionOptions = {}): Promise<Uint8Array> {
        this.requireReady();
        throwIfOffline('encrypt', this.apiClient.isAuthenticated);

        // Validate input data and options
        const validData = InputValidator.validateEncryptionData(data);
        const validOptions = InputValidator.validateEncryptionOptions(options);

        const dataBytes = typeof validData === 'string' ? new TextEncoder().encode(validData) : validData;
        const recipients = validOptions.shareWithUsers || [];

        // MANDATORY: Validate encryption with server (quota, permissions, etc.)
        const validation = await this.apiClient.validateEncryption(dataBytes.length, recipients);

        if (!validation.allowed) {
            throw new Error('Encryption not permitted by server');
        }

        // All cryptographic operations use native WebCrypto APIs only.
        // The crypto operations are local but resource registration is server-controlled
        const encryptionKey = crypto.getRandomValues(new Uint8Array(32));

        // Register resource with server - resource ID comes from server
        await this.apiClient.registerResource(
            this.bufferToBase64(encryptionKey),
            recipients,
            validOptions.shareWithGroups || []
        );

        // Perform local encryption with the key
        // All cryptographic operations use native WebCrypto APIs only.
        return this.performLocalEncryption(dataBytes, encryptionKey);
    }

    /**
     * Decrypt data - REQUIRES server permission validation
     * All decryption operations must be authorized by server
     */
    async decrypt(encryptedData: Uint8Array, options: DecryptionOptions = {}): Promise<string | Uint8Array> {
        this.requireReady();
        throwIfOffline('decrypt', this.apiClient.isAuthenticated);

        // Extract resource ID from encrypted data (simplified for demo)
        const resourceId = this.extractResourceId(encryptedData);

        // MANDATORY: Validate decryption with server
        const validation = await this.apiClient.validateDecryption(resourceId);

        if (!validation.allowed) {
            throw new Error('Decryption not permitted by server');
        }

        // Perform local decryption
        const decrypted = await this.performLocalDecryption(encryptedData, validation.encryptionKey);

        return options.outputFormat === 'uint8array' ? decrypted : new TextDecoder().decode(decrypted);
    }

    /**
     * Create group - REQUIRES server-generated group ID
     * No local group creation - server controls all group operations
     */
    async createGroup(users: string[]): Promise<string> {
        this.requireReady();
        throwIfOffline('createGroup', this.apiClient.isAuthenticated);

        // ALL group creation goes through server
        const group = await this.apiClient.createGroup(users);

        return group.groupId;
    }

    /**
     * Update group members - REQUIRES server validation
     * All group modifications must be server-authorized
     */
    async updateGroupMembers(groupId: string, args: { usersToAdd?: string[]; usersToRemove?: string[] }): Promise<void> {
        this.requireReady();
        throwIfOffline('updateGroupMembers', this.apiClient.isAuthenticated);

        await this.apiClient.updateGroupMembers(
            groupId,
            args.usersToAdd || [],
            args.usersToRemove || []
        );
    }

    /**
     * Share resources - REQUIRES server validation
     * All sharing operations must be authorized by server
     */
    async share(resourceIds: string[], options: { shareWithUsers?: string[]; shareWithGroups?: string[] }): Promise<void> {
        this.requireReady();
        throwIfOffline('share', this.apiClient.isAuthenticated);

        // Share each resource through server
        for (const resourceId of resourceIds) {
            await this.apiClient.shareResource(
                resourceId,
                options.shareWithUsers || [],
                options.shareWithGroups || []
            );
        }
    }

    /**
     * Generate verification key for device management
     * REQUIRES server validation for key registration
     */
    async generateVerificationKey(): Promise<VerificationKey> {
        this.requireReady();
        throwIfOffline('generateVerificationKey', this.apiClient.isAuthenticated);

        // Generate key pair locally using WebCrypto
        const keyPair = await crypto.subtle.generateKey(
            {
                name: 'ECDSA',
                namedCurve: 'P-256'
            },
            true,
            ['sign', 'verify']
        );

        const privateKeyBuffer = await crypto.subtle.exportKey('raw', keyPair.privateKey);
        const publicKeyBuffer = await crypto.subtle.exportKey('raw', keyPair.publicKey);

        const verificationKey: VerificationKey = {
            privateKey: this.bufferToBase64(new Uint8Array(privateKeyBuffer)),
            publicKey: this.bufferToBase64(new Uint8Array(publicKeyBuffer))
        };

        // Register verification key with server - MANDATORY
        await this.apiClient.registerVerificationKey(verificationKey.publicKey);

        return verificationKey;
    }

    /**
     * Get resource ID from encrypted data
     * Server validates access permissions
     */
    async getResourceId(encryptedData: Uint8Array): Promise<string> {
        this.requireReady();
        throwIfOffline('getResourceId', this.apiClient.isAuthenticated);

        const resourceId = this.extractResourceId(encryptedData);
        
        // Validate access with server
        const hasAccess = await this.apiClient.validateResourceAccess(resourceId);
        if (!hasAccess) {
            throw new Error('Access denied to resource');
        }

        return resourceId;
    }

    /**
     * Encrypt data with advanced options
     * All operations require server validation
     */
    async encryptData(data: Uint8Array, options: StreamEncryptionOptions = {}): Promise<Uint8Array> {
        this.requireReady();
        throwIfOffline('encryptData', this.apiClient.isAuthenticated);

        const recipients = options.shareWithUsers || [];
        
        // MANDATORY: Validate encryption with server
        const validation = await this.apiClient.validateEncryption(data.length, recipients);
        
        if (!validation.allowed) {
            throw new Error('Encryption not permitted by server');
        }

        // Progress tracking
        if (options.onProgress) {
            options.onProgress({ currentBytes: 0, totalBytes: data.length, percentage: 0 });
        }

        // All cryptographic operations use native WebCrypto APIs only
        const encryptionKey = crypto.getRandomValues(new Uint8Array(32));
        
        // Register resource with server
        await this.apiClient.registerResource(
            this.bufferToBase64(encryptionKey),
            recipients,
            options.shareWithGroups || []
        );

        // Perform encryption with progress
        const encrypted = await this.performLocalEncryption(data, encryptionKey);

        if (options.onProgress) {
            options.onProgress({ currentBytes: data.length, totalBytes: data.length, percentage: 100 });
        }

        return encrypted;
    }

    /**
     * Decrypt data with advanced options
     * Server authorization required
     */
    async decryptData(encryptedData: Uint8Array, options: DecryptionOptions = {}): Promise<Uint8Array | string> {
        this.requireReady();
        throwIfOffline('decryptData', this.apiClient.isAuthenticated);

        const resourceId = this.extractResourceId(encryptedData);
        
        // MANDATORY: Validate decryption with server
        const validation = await this.apiClient.validateDecryption(resourceId);
        
        if (!validation.allowed) {
            throw new Error('Decryption not permitted by server');
        }

        // Perform decryption
        const decrypted = await this.performLocalDecryption(encryptedData, validation.encryptionKey);
        
        return options.outputFormat === 'uint8array' ? decrypted : new TextDecoder().decode(decrypted);
    }

    /**
     * Create encryption session for multiple operations
     * Session validated with server
     */
    async createEncryptionSession(options: SharingOptions = {}): Promise<EncryptionSession> {
        this.requireReady();
        throwIfOffline('createEncryptionSession', this.apiClient.isAuthenticated);

        // Create session with server
        const session = await this.apiClient.createEncryptionSession(options);

        return {
            resourceId: session.resourceId,
            encrypt: async (data: string | Uint8Array): Promise<Uint8Array> => {
                const dataBytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
                return this.encryptData(dataBytes, options);
            },
            encryptData: async (data: Uint8Array): Promise<Uint8Array> => {
                return this.encryptData(data, options);
            }
        };
    }

    /**
     * Get device list for current user
     * All device data comes from server
     */
    async getDeviceList(): Promise<Device[]> {
        this.requireReady();
        throwIfOffline('getDeviceList', this.apiClient.isAuthenticated);

        if (!this.currentUserId) {
            throw new Error('No user ID available');
        }

        const identity = await this.apiClient.getIdentity(this.currentUserId);
        return identity.devices;
    }

    /**
     * Revoke a device
     * Server-controlled device management
     */
    async revokeDevice(deviceId: string): Promise<void> {
        this.requireReady();
        throwIfOffline('revokeDevice', this.apiClient.isAuthenticated);

        await this.apiClient.revokeDevice(deviceId);
    }

    /**
     * Set verification method for identity
     * Server validates and stores verification data
     */
    async setVerificationMethod(verification: VerificationMethod): Promise<void> {
        this.requireReady();
        throwIfOffline('setVerificationMethod', this.apiClient.isAuthenticated);

        await this.apiClient.setVerificationMethod(verification);
    }

    /**
     * Get available verification methods
     * Server returns allowed verification options
     */
    async getVerificationMethods(): Promise<VerificationMethod[]> {
        this.requireReady();
        throwIfOffline('getVerificationMethods', this.apiClient.isAuthenticated);

        return this.apiClient.getVerificationMethods();
    }

    /**
     * Stop the SDK and clear local data
     */
    async stop(): Promise<void> {
        this.setStatus(Status.STOPPED);
        
        // Secure cleanup of sensitive data
        this.secureCleanup();
        
        this.currentUserId = null;
        this.userSecret = null;
        this.deviceKeys = null;
        
        await this.keyStore.clear();
    }

    /**
     * Securely clean sensitive data from memory
     */
    private secureCleanup(): void {
        try {
            // Clear user secret securely
            if (this.userSecret) {
                secureWipe(this.userSecret);
                this.userSecret = null;
            }

            // Clear device keys if they exist
            if (this.deviceKeys?.signatureKeyPair?.privateKey) {
                // Note: WebCrypto keys are not directly accessible for overwriting
                // but we can clear the references to help GC
                this.deviceKeys = null;
            }

            // Clear any sensitive configuration data
            // (apiKey should not be wiped as it might be needed for reconnection)

            // Force garbage collection if available (non-standard)
            if (typeof global !== 'undefined' && 'gc' in global && typeof (global as { gc?: () => void }).gc === 'function') {
                (global as { gc: () => void }).gc();
            }
        } catch (error) {
            console.warn('[VAULTIC SDK] Secure cleanup encountered an error:', error);
        }
    }

    // Getters
    get appId(): string {
        return this.config.appId;
    }

    get statusName(): string {
        return this.status;
    }

    get deviceId(): string | null {
        return this.apiClient.deviceId;
    }

    // Private methods

    private async authenticateWithServer(): Promise<void> {
        if (!this.deviceKeys) {
            throw new DeviceNotRegisteredError();
        }

        // Request challenge from server
        const challenge = await this.apiClient.requestChallenge(this.deviceId || undefined);

        // Sign challenge with device signature key
        const signedChallenge = await this.signChallenge(challenge.challenge, this.deviceKeys.signatureKeyPair.privateKey);

        // Extract public keys
        const publicKeys = await this.extractPublicKeys(this.deviceKeys);

        // Authenticate with server
        await this.apiClient.authenticate(challenge.challengeId, signedChallenge, {
            publicSignatureKey: publicKeys.signatureKey,
            publicEncryptionKey: publicKeys.encryptionKey
        });
    }

    private async generateDeviceKeys(): Promise<DeviceKeys> {
        const signatureKeyPair = await crypto.subtle.generateKey(
            {
                name: 'ECDSA',
                namedCurve: CRYPTO_PARAMS.ECDSA_CURVE
            },
            true,
            ['sign', 'verify']
        );

        const encryptionKeyPair = await crypto.subtle.generateKey(
            {
                name: 'ECDH',
                namedCurve: CRYPTO_PARAMS.ECDH_CURVE
            },
            true,
            ['deriveKey']
        );

        return { signatureKeyPair, encryptionKeyPair };
    }

    private async extractPublicKeys(deviceKeys: DeviceKeys): Promise<{ signatureKey: string; encryptionKey: string }> {
        const signatureKeyBuffer = await crypto.subtle.exportKey('raw', deviceKeys.signatureKeyPair.publicKey);
        const encryptionKeyBuffer = await crypto.subtle.exportKey('raw', deviceKeys.encryptionKeyPair.publicKey);

        return {
            signatureKey: this.bufferToBase64(new Uint8Array(signatureKeyBuffer)),
            encryptionKey: this.bufferToBase64(new Uint8Array(encryptionKeyBuffer))
        };
    }

    private async deriveUserSecret(passphrase: string): Promise<Uint8Array> {
        const encoder = new TextEncoder();
        const passphraseBuffer = encoder.encode(passphrase);

        const key = await crypto.subtle.importKey(
            'raw',
            passphraseBuffer,
            'PBKDF2',
            false,
            ['deriveKey']
        );

        const salt = encoder.encode(this.config.appId); // Use app ID as salt

        const derivedKey = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt,
                iterations: CRYPTO_PARAMS.PBKDF2_ITERATIONS,
                hash: CRYPTO_PARAMS.PBKDF2_HASH
            },
            key,
            { name: 'AES-GCM', length: CRYPTO_PARAMS.AES_KEY_LENGTH },
            true,
            ['encrypt', 'decrypt']
        );

        const keyBuffer = await crypto.subtle.exportKey('raw', derivedKey);
        return new Uint8Array(keyBuffer);
    }

    private async signChallenge(challenge: string, privateKey: CryptoKey): Promise<string> {
        const encoder = new TextEncoder();
        const challengeBuffer = encoder.encode(challenge);

        const signature = await crypto.subtle.sign(
            { name: 'ECDSA', hash: 'SHA-256' },
            privateKey,
            challengeBuffer.buffer
        );

        return this.bufferToBase64(new Uint8Array(signature));
    }

    private setStatus(newStatus: Status): void {
        const previousStatus = this.status;
        this.status = newStatus;

        const event: StatusChangeEvent = {
            previousStatus,
            status: newStatus,
            timestamp: Date.now()
        };

        this.emit('statusChange', event);
    }

    private requireReady(): void {
        if (this.status !== Status.READY) {
            throw new Error(`Operation requires READY status. Current status: ${this.status}`);
        }
    }

    private bufferToBase64(buffer: Uint8Array): string {
        // Prevent buffer overflow by checking size limits
        if (buffer.length > CRYPTO_PARAMS.MAX_BUFFER_SIZE) {
            throw new Error('Buffer too large for base64 conversion');
        }
        
        // Use chunked conversion for large buffers to prevent stack overflow
        if (buffer.length > CRYPTO_PARAMS.CHUNK_SIZE) {
            let result = '';
            for (let i = 0; i < buffer.length; i += CRYPTO_PARAMS.CHUNK_SIZE) {
                const chunk = buffer.slice(i, i + CRYPTO_PARAMS.CHUNK_SIZE);
                result += btoa(String.fromCharCode(...chunk));
            }
            return result;
        }
        
        return btoa(String.fromCharCode(...buffer));
    }

    private base64ToBuffer(base64: string): Uint8Array {
        // Validate base64 input
        if (!/^[A-Za-z0-9+/]*={0,2}$/.test(base64)) {
            throw new Error('Invalid base64 string');
        }
        
        // Prevent excessive memory allocation
        if (base64.length > CRYPTO_PARAMS.MAX_BASE64_SIZE) {
            throw new Error('Base64 string too large');
        }
        
        try {
            return new Uint8Array(atob(base64).split('').map(char => char.charCodeAt(0)));
        } catch (error) {
            throw new Error('Failed to decode base64 string');
        }
    }

    // All cryptographic operations use native WebCrypto APIs only.
    private async performLocalEncryption(data: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
        const cryptoKey = await crypto.subtle.importKey('raw', key.slice().buffer, { name: 'AES-GCM' }, false, ['encrypt']);
        const iv = crypto.getRandomValues(new Uint8Array(CRYPTO_PARAMS.AES_IV_LENGTH));
        const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, data.slice().buffer);

        // Combine IV and encrypted data
        const result = new Uint8Array(iv.length + encrypted.byteLength);
        result.set(iv);
        result.set(new Uint8Array(encrypted), iv.length);

        return result;
    }

    private async performLocalDecryption(encryptedData: Uint8Array, keyBase64: string): Promise<Uint8Array> {
        const key = this.base64ToBuffer(keyBase64);
        const cryptoKey = await crypto.subtle.importKey('raw', key.slice().buffer, { name: 'AES-GCM' }, false, ['decrypt']);

        const iv = encryptedData.slice(0, CRYPTO_PARAMS.AES_IV_LENGTH);
        const encrypted = encryptedData.slice(CRYPTO_PARAMS.AES_IV_LENGTH);

        const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, encrypted);
        return new Uint8Array(decrypted);
    }

    private extractResourceId(encryptedData: Uint8Array): string {
        // Simplified extraction for demo - real implementation would parse the encrypted format
        return `resource_${  this.bufferToBase64(encryptedData.slice(0, 16))}`;
    }
}

/**
 * SECURITY ARCHITECTURE SUMMARY:
 * 
 * This VaulticClient implementation ensures that EVERY critical operation
 * requires server validation and approval:
 * 
 * 1. Device Registration: Device IDs generated server-side only
 * 2. Authentication: Challenge-response with server-signed challenges
 * 3. Encryption: Server validates quota and permissions before encryption
 * 4. Decryption: Server authorizes each decryption operation
 * 5. Group Management: All group operations server-controlled
 * 6. Resource Sharing: Server validates all sharing operations
 * 
 * All cryptographic operations use native WebCrypto APIs only.
 */ 