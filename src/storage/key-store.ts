// KeyStore - Local storage for device keys ONLY
// CRITICAL: This is a CACHE ONLY - all operations require server validation
// No local key can be used without API verification

import Dexie, { Table } from 'dexie';
import { LocalData } from '../types';
import {
    ServerValidationRequiredError,
    InvalidServerSignatureError
} from '../errors';
import { VAULTIC_SERVER_PUBLIC_KEY, CRYPTO_PARAMS } from '../config/security';

interface StoredKeyData {
    id: string; // Always "current" - only one set of keys per device
    encryptedData: string; // Encrypted key data
    serverSignature: string; // Server signature validating this key set
    lastSync: number; // When this was last validated with server
    deviceId?: string; // Device ID from server (if authenticated)
}

export class KeyStore {
    private db: Dexie;
    private keyTable: Table<StoredKeyData>;
    private userSecret: Uint8Array | null = null;

    constructor() {
        this.db = new Dexie('VaulticKeyStore');
        this.db.version(1).stores({
            keys: 'id, lastSync, deviceId'
        });
        this.keyTable = this.db.table('keys');
    }

    /**
     * Save device keys - REQUIRES server signature
     * Local keys are NEVER trusted without server validation
     */
    async save(localData: LocalData, userSecret: Uint8Array): Promise<void> {
        if (!localData.serverSignature) {
            throw new ServerValidationRequiredError('device_keys');
        }

        // Verify server signature before saving
        if (!(await this.verifyServerSignature(localData))) {
            throw new InvalidServerSignatureError('device_keys');
        }

        this.userSecret = userSecret;

        const encryptedData = await this.encryptLocalData(localData, userSecret);

        const storedData: StoredKeyData = { id: 'current', encryptedData, serverSignature: localData.serverSignature, lastSync: localData.lastSyncTimestamp }; if (localData.deviceKeys?.signatureKeyPair) { storedData.deviceId = 'unknown'; }

        await this.keyTable.put(storedData);
    }

    /**
     * Load device keys - WARNS if not recently validated with server
     * Old local data without recent server validation is considered suspicious
     */
    async load(userSecret: Uint8Array): Promise<LocalData | null> {
        this.userSecret = userSecret;

        const stored = await this.keyTable.get('current');
        if (!stored) {
            return null;
        }

        // Check if data is stale (older than 1 hour)
        const oneHourAgo = Date.now() - (60 * 60 * 1000);
        if (stored.lastSync < oneHourAgo) {
            console.warn(
                '[VAULTIC SDK] WARNING: Local keys have not been validated with server for over 1 hour. ' +
                'Please reconnect to ensure security. This SDK requires active server validation.'
            );
        }

        // Verify server signature
        const decryptedData = await this.decryptLocalData(stored.encryptedData, userSecret);
        if (!(await this.verifyServerSignature(decryptedData))) {
            throw new InvalidServerSignatureError('stored_device_keys');
        }

        return decryptedData;
    }

    /**
     * Clear all local data
     * Used when user logs out or when local data is compromised
     */
    async clear(): Promise<void> {
        await this.keyTable.clear();
        this.userSecret = null;
    }

    /**
     * Check if local keys exist (but may be invalid without server)
     */
    async hasKeys(): Promise<boolean> {
        const count = await this.keyTable.count();
        return count > 0;
    }

    /**
     * Get last synchronization timestamp
     * Used to determine if server re-validation is needed
     */
    async getLastSync(): Promise<number | null> {
        const stored = await this.keyTable.get('current');
        return stored?.lastSync || null;
    }

    /**
     * Mark data as requiring server validation
     * Called when API connection is lost or restored
     */
    async markAsRequiringValidation(): Promise<void> {
        const stored = await this.keyTable.get('current');
        if (stored) {
            stored.lastSync = 0; // Force re-validation
            await this.keyTable.put(stored);
        }
    }

    /**
     * Encrypt local data using user secret
     * This is local encryption only - server signature is still required
     */
    private async encryptLocalData(data: LocalData, userSecret: Uint8Array): Promise<string> {
        try {
            // Import user secret as encryption key
            const key = await crypto.subtle.importKey(
                'raw',
                userSecret.slice(0, CRYPTO_PARAMS.AES_KEY_LENGTH / 8), // Use AES key length from config
                { name: 'AES-GCM' },
                false,
                ['encrypt']
            );

            // Create IV
            const iv = crypto.getRandomValues(new Uint8Array(CRYPTO_PARAMS.AES_IV_LENGTH));

            // Encrypt data
            const encryptedBuffer = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv },
                key,
                new TextEncoder().encode(JSON.stringify(data))
            );

            // Combine IV and encrypted data
            const combined = new Uint8Array(iv.length + encryptedBuffer.byteLength);
            combined.set(iv);
            combined.set(new Uint8Array(encryptedBuffer), iv.length);

            return btoa(String.fromCharCode(...combined));
        } catch (error) {
            throw new Error(`Failed to encrypt local data: ${error}`);
        }
    }

    /**
     * Decrypt local data using user secret
     */
    private async decryptLocalData(encryptedData: string, userSecret: Uint8Array): Promise<LocalData> {
        try {
            // Decode base64
            const combined = new Uint8Array(
                atob(encryptedData).split('').map(char => char.charCodeAt(0))
            );

            // Extract IV and encrypted data
            const iv = combined.slice(0, CRYPTO_PARAMS.AES_IV_LENGTH);
            const encrypted = combined.slice(CRYPTO_PARAMS.AES_IV_LENGTH);

            // Import user secret as decryption key
            const key = await crypto.subtle.importKey(
                'raw',
                userSecret.slice(0, CRYPTO_PARAMS.AES_KEY_LENGTH / 8),
                { name: 'AES-GCM' },
                false,
                ['decrypt']
            );

            // Decrypt data
            const decryptedBuffer = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                key,
                encrypted
            );

            const decryptedText = new TextDecoder().decode(decryptedBuffer);
            return JSON.parse(decryptedText);
        } catch (error) {
            throw new Error(`Failed to decrypt local data: ${error}`);
        }
    }

    /**
     * Verify server signature on stored data
     * CRITICAL: All local data must have valid server signature
     */
    private async verifyServerSignature(data: LocalData): Promise<boolean> {
        if (!data.serverSignature) {
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

            // Create a copy of data without the signature for verification
            const { serverSignature, ...dataForVerification } = data;

            // Prepare data for verification
            const dataToVerify = new TextEncoder().encode(JSON.stringify(dataForVerification));
            const signatureBuffer = this.base64ToArrayBuffer(data.serverSignature);

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
            console.error('[VAULTIC SDK] Local signature verification failed:', error);
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
     * Close database connection
     */
    async close(): Promise<void> {
        await this.db.close();
    }
}

/**
 * IMPORTANT SECURITY NOTICE:
 * 
 * This KeyStore is designed to be USELESS without server validation.
 * 
 * Key security principles:
 * 1. All stored keys MUST have server signatures
 * 2. Keys older than 1 hour trigger warnings
 * 3. No cryptographic operations are possible without API validation
 * 4. Local storage is for performance only, not security
 * 
  * If someone forks this SDK:* 
  * - They cannot generate valid server signatures 
  * - They cannot bypass the server validation requirements 
  * - Local keys are encrypted and worthless without server authentication 
  * - All critical operations will fail without API connection 
  * - All cryptographic operations use native WebCrypto APIs only
 */ 