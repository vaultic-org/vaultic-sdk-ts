// Security configuration and constants
// This file contains cryptographic parameters and server public keys

/**
 * Vaultic Server Public Key for signature verification
 * This key is used to verify all server signatures
 * 
 */
export const VAULTIC_SERVER_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEv2D725TePU4BzXvRLEtr96UdWOEB
JtaVe671IwXhBGE4bQHAiDOHK4SZeMXJ97FP8NU63BEw4LKXjJysp1zryA==
-----END PUBLIC KEY-----`;

/**
 * Cryptographic security parameters
 */
export const CRYPTO_PARAMS = {
    // Key derivation parameters
    PBKDF2_ITERATIONS: 100000,
    PBKDF2_HASH: 'SHA-256' as const,

    // Symmetric encryption
    AES_KEY_LENGTH: 256,
    AES_IV_LENGTH: 12,

    // Asymmetric cryptography
    ECDSA_CURVE: 'P-256' as const,
    ECDH_CURVE: 'P-256' as const,

    // Security limits
    MAX_BUFFER_SIZE: 1024 * 1024, // 1MB
    MAX_BASE64_SIZE: 1.5 * 1024 * 1024, // ~1MB decoded
    CHUNK_SIZE: 65536, // 64KB

    // Token expiration checking
    TOKEN_EXPIRY_TOLERANCE: 60 * 1000, // 1 minute tolerance

    // Local data validation
    MAX_LOCAL_DATA_AGE: 60 * 60 * 1000, // 1 hour
} as const;

/**
 * Server signature verification configuration
 */
export const SIGNATURE_CONFIG = {
    ALGORITHM: 'ECDSA' as const,
    HASH: 'SHA-256' as const,
    CURVE: 'P-256' as const,

    // Signature format validation
    MIN_SIGNATURE_LENGTH: 10,
    SIGNATURE_PREFIX: 'vaultic_',
} as const;

/**
 * Input validation limits
 */
export const VALIDATION_LIMITS = {
    MAX_STRING_SIZE: 100 * 1024 * 1024, // 100MB
    MAX_BINARY_SIZE: 1024 * 1024 * 1024, // 1GB
    MAX_RECIPIENTS: 1000,
    MAX_GROUP_MEMBERS: 1000,

    // API key format
    API_KEY_PREFIX: 'vlt_',
    MIN_API_KEY_LENGTH: 20,
    MAX_API_KEY_LENGTH: 200,
} as const;

/**
 * Error messages for security violations
 */
export const SECURITY_ERRORS = {
    BUFFER_TOO_LARGE: 'Buffer too large for secure processing',
    INVALID_BASE64: 'Invalid base64 string format',
    SIGNATURE_VERIFICATION_FAILED: 'Cryptographic signature verification failed',
    TOKEN_EXPIRED: 'Authentication token has expired',
    DATA_TOO_OLD: 'Local data is too old and requires server validation',
} as const;

/**
 * Constant-time comparison function to prevent timing attacks
 * Use this for comparing sensitive data like tokens, signatures, etc.
 */
export function constantTimeCompare(a: string | Uint8Array, b: string | Uint8Array): boolean {
    // Convert to Uint8Array if strings
    const bufferA = typeof a === 'string' ? new TextEncoder().encode(a) : a;
    const bufferB = typeof b === 'string' ? new TextEncoder().encode(b) : b;

    // If lengths differ, comparison is false but we still iterate to prevent timing
    if (bufferA.length !== bufferB.length) {
        // Still perform comparison to prevent early exit timing
        let result = 1; // Start with difference
        const maxLength = Math.max(bufferA.length, bufferB.length);
        
        for (let i = 0; i < maxLength; i++) {
            const byteA = i < bufferA.length ? bufferA[i]! : 0;
            const byteB = i < bufferB.length ? bufferB[i]! : 0;
            result |= byteA ^ byteB;
        }
        
        return false;
    }

    // Constant-time comparison
    let result = 0;
    for (let i = 0; i < bufferA.length; i++) {
        result |= bufferA[i]! ^ bufferB[i]!;
    }

    return result === 0;
}

/**
 * Secure memory cleanup utilities
 */
export function secureWipe(buffer: Uint8Array): void {
    // Overwrite with random data first
    crypto.getRandomValues(buffer);
    // Then zero out
    buffer.fill(0);
}

/**
 * Rate limiting configuration for security operations
 */
export const RATE_LIMITS = {
    // Maximum signature verification attempts per minute
    MAX_SIGNATURE_VERIFICATIONS: 100,
    // Maximum authentication attempts per minute  
    MAX_AUTH_ATTEMPTS: 10,
    // Minimum delay between operations (milliseconds)
    MIN_OPERATION_DELAY: 100,
} as const; 