// API Client - Core communication layer with Vaultic API
// ALL critical operations MUST go through this client - no local alternatives

import {
    VaulticConfig,
    ApiResponse,
    Challenge,
    AuthenticationToken,
    Device,
    Group,
    Resource,
    Identity
} from '../types';
import {
    ApiConnectionRequiredError,
    InvalidServerSignatureError,
    InvalidApiKeyError,
    AuthenticationRequiredError,
    throwIfOffline
} from '../errors';
import { VAULTIC_SERVER_PUBLIC_KEY } from '../config/security';

export class ApiClient {
    private config: VaulticConfig;
    private baseUrl: string;
    private authToken: AuthenticationToken | null = null;
    private isConnected: boolean = false;

    constructor(config: VaulticConfig) {
        this.config = config;
        this.baseUrl = config.apiUrl || 'https://api.vaultic.app';

        // Validate API key format - must be from Vaultic
        if (!config.apiKey.startsWith('vlt_')) {
            throw new InvalidApiKeyError();
        }
    }

    /**
     * Initialize connection and validate API key with server
     * This MUST be called before any operation - no offline mode
     */
    async initialize(): Promise<void> {
        try {
            const response = await this.makeRequest<{ valid: boolean; appId: string }>('GET', '/v1/auth/validate', {
                headers: { 'X-API-Key': this.config.apiKey }
            });

            if (!response.data?.valid || response.data.appId !== this.config.appId) {
                throw new InvalidApiKeyError();
            }

            this.isConnected = true;
        } catch (error) {
            this.isConnected = false;
            throw new ApiConnectionRequiredError('initialize');
        }
    }

    /**
     * Request authentication challenge from server
     * No local challenge generation - server authority only
     */
    async requestChallenge(deviceId?: string): Promise<Challenge> {
        throwIfOffline('requestChallenge', this.isConnected);

        const response = await this.makeRequest<Challenge>('POST', '/v1/auth/challenge', {
            body: { deviceId, appId: this.config.appId }
        });

        if (!response.data || !(await this.verifyServerSignature(response.data, response.data.signature))) {
            throw new InvalidServerSignatureError('challenge');
        }

        return response.data;
    }

    /**
     * Authenticate with server using signed challenge
     * All authentication tokens come from server - no local generation
     */
    async authenticate(challengeId: string, signedChallenge: string, deviceKeys: {
        publicSignatureKey: string;
        publicEncryptionKey: string;
    }): Promise<AuthenticationToken> {
        throwIfOffline('authenticate', this.isConnected);

        const response = await this.makeRequest<AuthenticationToken>('POST', '/v1/auth/authenticate', {
            body: {
                challengeId,
                signedChallenge,
                deviceKeys,
                appId: this.config.appId
            }
        });

        if (!response.data || !(await this.verifyServerSignature(response.data, response.data.signature))) {
            throw new InvalidServerSignatureError('authentication_token');
        }

        this.authToken = response.data;
        return response.data;
    }

    /**
     * Register new device with server
     * Device IDs are ONLY generated server-side - no local device creation
     */
    async registerDevice(publicKeys: {
        signatureKey: string;
        encryptionKey: string;
    }): Promise<Device> {
        throwIfOffline('registerDevice', this.isConnected);
        this.requireAuth();

        const response = await this.makeRequest<Device>('POST', '/v1/devices', {
            body: {
                publicSignatureKey: publicKeys.signatureKey,
                publicEncryptionKey: publicKeys.encryptionKey,
                appId: this.config.appId
            }
        });

        if (!response.data || !(await this.verifyServerSignature(response.data, response.data.serverSignature))) {
            throw new InvalidServerSignatureError('device');
        }

        return response.data;
    }

    /**
     * Get user identity from server
     * All identity data comes from server - no local identity management
     */
    async getIdentity(userId: string): Promise<Identity> {
        throwIfOffline('getIdentity', this.isConnected);
        this.requireAuth();

        const response = await this.makeRequest<Identity>('GET', `/v1/users/${userId}`, {});

        if (!response.data || !(await this.verifyServerSignature(response.data, response.data.serverSignature))) {
            throw new InvalidServerSignatureError('identity');
        }

        return response.data;
    }

    /**
     * Create group via server
     * Group IDs and management are ONLY server-side - no local group creation
     */
    async createGroup(members: string[]): Promise<Group> {
        throwIfOffline('createGroup', this.isConnected);
        this.requireAuth();

        const response = await this.makeRequest<Group>('POST', '/v1/groups', {
            body: { members, appId: this.config.appId }
        });

        if (!response.data || !(await this.verifyServerSignature(response.data, response.data.serverSignature))) {
            throw new InvalidServerSignatureError('group');
        }

        return response.data;
    }

    /**
     * Update group members via server
     * All group modifications require server validation
     */
    async updateGroupMembers(groupId: string, membersToAdd: string[], membersToRemove: string[]): Promise<Group> {
        throwIfOffline('updateGroupMembers', this.isConnected);
        this.requireAuth();

        const response = await this.makeRequest<Group>('PATCH', `/v1/groups/${groupId}/members`, {
            body: { membersToAdd, membersToRemove }
        });

        if (!response.data || !(await this.verifyServerSignature(response.data, response.data.serverSignature))) {
            throw new InvalidServerSignatureError('group');
        }

        return response.data;
    }

    /**
     * Get group from server
     * No local group retrieval - server is source of truth
     */
    async getGroup(groupId: string): Promise<Group> {
        throwIfOffline('getGroup', this.isConnected);
        this.requireAuth();

        const response = await this.makeRequest<Group>('GET', `/v1/groups/${groupId}`, {});

        if (!response.data || !(await this.verifyServerSignature(response.data, response.data.serverSignature))) {
            throw new InvalidServerSignatureError('group');
        }

        return response.data;
    }

    /**
     * Register resource with server
     * Resource IDs are ONLY generated server-side
     */
    async registerResource(encryptionKey: string, sharedWith: string[], groups: string[]): Promise<Resource> {
        throwIfOffline('registerResource', this.isConnected);
        this.requireAuth();

        const response = await this.makeRequest<Resource>('POST', '/v1/resources', {
            body: { encryptionKey, sharedWith, groups }
        });

        if (!response.data || !(await this.verifyServerSignature(response.data, response.data.serverSignature))) {
            throw new InvalidServerSignatureError('resource');
        }

        return response.data;
    }

    /**
     * Share resource via server
     * All sharing operations require server validation
     */
    async shareResource(resourceId: string, shareWith: string[], groups: string[]): Promise<void> {
        throwIfOffline('shareResource', this.isConnected);
        this.requireAuth();

        await this.makeRequest('POST', `/v1/resources/${resourceId}/share`, {
            body: { shareWith, groups }
        });
    }

    /**
     * Validate encryption operation with server
     * All encryption operations must be validated for quota/permissions
     */
    async validateEncryption(dataSize: number, recipients: string[]): Promise<{ allowed: boolean; resourceId: string }> {
        throwIfOffline('validateEncryption', this.isConnected);
        this.requireAuth();

        const response = await this.makeRequest<{ allowed: boolean; resourceId: string }>('POST', '/v1/encryption/validate', {
            body: { dataSize, recipients }
        });

        return response.data!;
    }

    /**
     * Validate decryption operation with server
     * All decryption operations must be validated for permissions
     */
    async validateDecryption(resourceId: string): Promise<{ allowed: boolean; encryptionKey: string }> {
        throwIfOffline('validateDecryption', this.isConnected);
        this.requireAuth();

        const response = await this.makeRequest<{ allowed: boolean; encryptionKey: string }>('POST', '/v1/decryption/validate', {
            body: { resourceId }
        });

        return response.data!;
    }

    /**   * Register verification key with server   * All verification keys must be server-registered   */  async registerVerificationKey(publicKey: string): Promise<void> { throwIfOffline('registerVerificationKey', this.isConnected); this.requireAuth(); await this.makeRequest('POST', '/v1/verification-keys', { body: { publicKey } }); }  /**   * Validate resource access with server   * All resource access requires server authorization   */  async validateResourceAccess(resourceId: string): Promise<boolean> { throwIfOffline('validateResourceAccess', this.isConnected); this.requireAuth(); const response = await this.makeRequest<{ hasAccess: boolean }>('GET', `/v1/resources/${resourceId}/access`, {}); return response.data?.hasAccess || false; }  /**   * Create encryption session with server   * All sessions are server-managed   */  async createEncryptionSession(options: any): Promise<{ resourceId: string; sessionId: string }> { throwIfOffline('createEncryptionSession', this.isConnected); this.requireAuth(); const response = await this.makeRequest<{ resourceId: string; sessionId: string }>('POST', '/v1/encryption/sessions', { body: options }); return response.data!; }  /**   * Revoke device via server   * Only server can revoke devices   */  async revokeDevice(deviceId: string): Promise<void> { throwIfOffline('revokeDevice', this.isConnected); this.requireAuth(); await this.makeRequest('DELETE', `/v1/devices/${deviceId}`, {}); }  /**   * Set verification method via server   * Server stores and validates verification methods   */  async setVerificationMethod(verification: any): Promise<void> { throwIfOffline('setVerificationMethod', this.isConnected); this.requireAuth(); await this.makeRequest('POST', '/v1/verification-methods', { body: verification }); }  /**   * Get verification methods from server   * Server returns available verification options   */  async getVerificationMethods(): Promise<any[]> { throwIfOffline('getVerificationMethods', this.isConnected); this.requireAuth(); const response = await this.makeRequest<any[]>('GET', '/v1/verification-methods', {}); return response.data || []; }  /**   * Generic API request method with error handling   */
    private async makeRequest<T = any>(
        method: string,
        endpoint: string,
        options: {
            body?: any;
            headers?: Record<string, string>;
        }
    ): Promise<ApiResponse<T>> {
        const url = `${this.baseUrl}${endpoint}`;
        const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            'X-API-Key': this.config.apiKey,
            ...options.headers
        };

        if (this.authToken) {
            headers['Authorization'] = `Bearer ${this.authToken.token}`;
        }

        try {
            const fetchOptions: RequestInit = {
                method,
                headers
            };

            if (options.body) {
                fetchOptions.body = JSON.stringify(options.body);
            }

            const response = await fetch(url, fetchOptions);

            if (!response.ok) {
                const error = await response.json().catch(() => ({ message: 'Unknown error' }));
                throw new Error(error.message || `API request failed: ${response.status}`);
            }

            const data = await response.json();
            return data;
        } catch (error) {
            // Network or parsing errors indicate API unavailability
            this.isConnected = false;
            throw new ApiConnectionRequiredError(`${method} ${endpoint}`);
        }
    }

    /**
     * Verify server signature to prevent tampering
     * Critical security feature - all server data must be signed
     */
    private async verifyServerSignature(data: any, signature: string): Promise<boolean> {
        if (!signature || signature.length === 0) {
            return false;
        }

        try {
            // Import server public key
            const serverPublicKey = await crypto.subtle.importKey(
                'spki',
                this.pemToArrayBuffer(VAULTIC_SERVER_PUBLIC_KEY),
                {
                    name: 'ECDSA',
                    namedCurve: 'P-256'
                },
                false,
                ['verify']
            );

            // Prepare data for verification
            const dataToVerify = new TextEncoder().encode(JSON.stringify(data));
            const signatureBuffer = this.base64ToArrayBuffer(signature);

            // Verify the signature
            return await crypto.subtle.verify(
                {
                    name: 'ECDSA',
                    hash: 'SHA-256'
                },
                serverPublicKey,
                signatureBuffer,
                dataToVerify
            );
        } catch (error) {
            console.error('[VAULTIC SDK] Signature verification failed:', error);
            return false;
        }
    }

    /**
     * Convert PEM to ArrayBuffer
     */
    private pemToArrayBuffer(pem: string): ArrayBuffer {
        const b64 = pem
            .replace(/-----BEGIN PUBLIC KEY-----/, '')
            .replace(/-----END PUBLIC KEY-----/, '')
            .replace(/\s/g, '');
        return this.base64ToArrayBuffer(b64);
    }

    /**
     * Convert base64 to ArrayBuffer
     */
    private base64ToArrayBuffer(base64: string): ArrayBuffer {
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }

    /**
     * Require authentication for protected operations
     */
    private requireAuth(): void {
        if (!this.authToken) {
            throw new AuthenticationRequiredError();
        }

        // Check token expiration
        if (Date.now() > this.authToken.expiresAt) {
            this.authToken = null;
            throw new AuthenticationRequiredError();
        }
    }

    /**
     * Check if client is properly connected and authenticated
     */
    get isAuthenticated(): boolean {
        return this.isConnected && this.authToken !== null && Date.now() < this.authToken.expiresAt;
    }

    /**
     * Get current device ID (from server-issued token)
     */
    get deviceId(): string | null {
        return this.authToken?.deviceId || null;
    }

    /**
     * Get current user ID (from server-issued token)
     */
    get userId(): string | null {
        return this.authToken?.userId || null;
    }
} 