// Input Validation - Ensures all SDK inputs are properly validated
// Uses Zod for runtime type checking and data sanitization

import { z } from 'zod';
import { CryptoAlgorithm } from '../types';

// Base validation schemas
export const AppIdSchema = z.string()
  .min(3, 'App ID must be at least 3 characters')
  .max(100, 'App ID must be less than 100 characters')
  .regex(/^[a-zA-Z0-9_-]+$/, 'App ID can only contain alphanumeric characters, dashes, and underscores');

export const ApiKeySchema = z.string()
  .startsWith('vlt_', 'API key must start with "vlt_"')
  .min(20, 'API key must be at least 20 characters')
  .max(200, 'API key must be less than 200 characters');

export const UserIdSchema = z.string()
  .min(1, 'User ID cannot be empty')
  .max(255, 'User ID must be less than 255 characters')
  .regex(/^[a-zA-Z0-9_@.-]+$/, 'User ID contains invalid characters');

export const PassphraseSchema = z.string()
  .min(8, 'Passphrase must be at least 8 characters')
  .max(1000, 'Passphrase must be less than 1000 characters');

export const DeviceIdSchema = z.string()
  .regex(/^device_[a-zA-Z0-9_-]+$/, 'Invalid device ID format');

export const GroupIdSchema = z.string()
  .regex(/^group_[a-zA-Z0-9_-]+$/, 'Invalid group ID format');

export const ResourceIdSchema = z.string()
  .regex(/^resource_[a-zA-Z0-9_-]+$/, 'Invalid resource ID format');

// Configuration validation schemas
export const VaulticConfigSchema = z.object({
  appId: AppIdSchema,
  apiKey: ApiKeySchema,
  apiUrl: z.string().url('Invalid API URL').optional(),
  crypto: z.object({
    defaultAlgorithm: z.nativeEnum(CryptoAlgorithm).optional()
  }).optional()
});

export const RegistrationSchema = z.object({
  passphrase: PassphraseSchema.optional(),
  verificationKey: z.string().min(10, 'Verification key too short').optional(),
  enableMultiDevice: z.boolean().optional().default(true)
}).refine(
  data => data.passphrase || data.verificationKey,
  'Either passphrase or verification key must be provided'
);

export const VerificationMethodSchema = z.object({
  type: z.enum(['passphrase', 'verificationKey', 'email', 'phoneNumber']),
  value: z.string().min(1, 'Verification value cannot be empty').optional()
}).refine(
  data => {
    if (data.type === 'passphrase' && data.value) {
      return PassphraseSchema.safeParse(data.value).success;
    }
    if (data.type === 'email' && data.value) {
      return z.string().email().safeParse(data.value).success;
    }
    if (data.type === 'phoneNumber' && data.value) {
      return z.string().regex(/^\+[1-9]\d{1,14}$/).safeParse(data.value).success;
    }
    return data.value !== undefined;
  },
  'Invalid verification value for the specified type'
);

// Encryption validation schemas
export const EncryptionOptionsSchema = z.object({
  shareWithUsers: z.array(UserIdSchema).optional(),
  shareWithGroups: z.array(GroupIdSchema).optional(),
  paddingStep: z.number().int().min(1).max(1024).optional()
});

export const StreamEncryptionOptionsSchema = z.object({
  shareWithUsers: z.array(UserIdSchema).optional(),
  shareWithGroups: z.array(GroupIdSchema).optional(),
  paddingStep: z.number().int().min(1).max(1024).optional(),
  onProgress: z.function().optional(),
  maxChunkSize: z.number().int().min(1024).max(10 * 1024 * 1024).optional()
});

export const DecryptionOptionsSchema = z.object({
  outputFormat: z.enum(['string', 'uint8array']).optional().default('string')
});

// Data validation schemas
export const EncryptionDataSchema = z.union([
  z.string().max(100 * 1024 * 1024, 'Data too large (max 100MB)'), // 100MB string limit
  z.instanceof(Uint8Array).refine(
    data => data.length <= 1024 * 1024 * 1024, // 1GB binary limit
    'Data too large (max 1GB)'
  )
]);

export const SharingOptionsSchema = z.object({
  shareWithUsers: z.array(UserIdSchema).optional(),
  shareWithGroups: z.array(GroupIdSchema).optional(),
  shareWithProvisionalUsers: z.array(z.string().email()).optional()
});

// Group management schemas
export const CreateGroupSchema = z.object({
  users: z.array(UserIdSchema).min(1, 'Must specify at least one user').max(1000, 'Too many users')
});

export const UpdateGroupMembersSchema = z.object({
  usersToAdd: z.array(UserIdSchema).optional(),
  usersToRemove: z.array(UserIdSchema).optional()
}).refine(
  data => (data.usersToAdd && data.usersToAdd.length > 0) || 
          (data.usersToRemove && data.usersToRemove.length > 0),
  'Must specify users to add or remove'
);

// Validation error class
export class ValidationError extends Error {
  public readonly errors: z.ZodError;

  constructor(zodError: z.ZodError) {
    const message = zodError.errors.map(err => 
      `${err.path.join('.')}: ${err.message}`
    ).join(', ');
    
    super(`Validation failed: ${message}`);
    this.name = 'ValidationError';
    this.errors = zodError;
  }
}

// Validation utility class
export class InputValidator {
  /**
   * Validate and parse configuration
   */
  static validateConfig(config: unknown): ReturnType<typeof VaulticConfigSchema.parse> {
    try {
      return VaulticConfigSchema.parse(config);
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ValidationError(error);
      }
      throw error;
    }
  }

  /**
   * Validate user ID
   */
  static validateUserId(userId: unknown): string {
    try {
      return UserIdSchema.parse(userId);
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ValidationError(error);
      }
      throw error;
    }
  }

  /**
   * Validate registration data
   */
  static validateRegistration(registration: unknown): ReturnType<typeof RegistrationSchema.parse> {
    try {
      return RegistrationSchema.parse(registration);
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ValidationError(error);
      }
      throw error;
    }
  }

  /**
   * Validate verification method
   */
  static validateVerificationMethod(method: unknown): ReturnType<typeof VerificationMethodSchema.parse> {
    try {
      return VerificationMethodSchema.parse(method);
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ValidationError(error);
      }
      throw error;
    }
  }

  /**
   * Validate encryption data
   */
  static validateEncryptionData(data: unknown): string | Uint8Array {
    if (typeof data !== 'string' && !(data instanceof Uint8Array)) {
      throw new ValidationError(new z.ZodError([{
        code: 'invalid_type',
        expected: 'string',
        received: typeof data,
        path: ['data'],
        message: 'Data must be string or Uint8Array'
      }]));
    }
    return data;
  }

  /**
   * Validate encryption options
   */
  static validateEncryptionOptions(options: unknown): ReturnType<typeof EncryptionOptionsSchema.parse> {
    try {
      return EncryptionOptionsSchema.parse(options);
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ValidationError(error);
      }
      throw error;
    }
  }

  /**
   * Validate stream encryption options
   */
  static validateStreamEncryptionOptions(options: unknown): ReturnType<typeof StreamEncryptionOptionsSchema.parse> {
    try {
      return StreamEncryptionOptionsSchema.parse(options);
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ValidationError(error);
      }
      throw error;
    }
  }

  /**
   * Validate decryption options
   */
  static validateDecryptionOptions(options: unknown): ReturnType<typeof DecryptionOptionsSchema.parse> {
    try {
      return DecryptionOptionsSchema.parse(options);
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ValidationError(error);
      }
      throw error;
    }
  }

  /**
   * Validate group creation data
   */
  static validateCreateGroup(data: unknown): ReturnType<typeof CreateGroupSchema.parse> {
    try {
      return CreateGroupSchema.parse(data);
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ValidationError(error);
      }
      throw error;
    }
  }

  /**
   * Validate group member updates
   */
  static validateUpdateGroupMembers(data: unknown): ReturnType<typeof UpdateGroupMembersSchema.parse> {
    try {
      return UpdateGroupMembersSchema.parse(data);
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ValidationError(error);
      }
      throw error;
    }
  }

  /**
   * Validate sharing options
   */
  static validateSharingOptions(options: unknown): ReturnType<typeof SharingOptionsSchema.parse> {
    try {
      return SharingOptionsSchema.parse(options);
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ValidationError(error);
      }
      throw error;
    }
  }

  /**
   * Validate array of resource IDs
   */
  static validateResourceIds(ids: unknown): string[] {
    try {
      return z.array(ResourceIdSchema).parse(ids);
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ValidationError(error);
      }
      throw error;
    }
  }

  /**
   * Sanitize string input (remove potentially harmful characters)
   */
  static sanitizeString(input: string): string {
    return input
      .replace(/[<>]/g, '') // Remove HTML brackets
      .replace(/javascript:/gi, '') // Remove javascript: URLs
      .replace(/data:/gi, '') // Remove data: URLs
      .trim();
  }

  /**
   * Validate and sanitize email
   */
  static validateEmail(email: unknown): string {
    try {
      const validEmail = z.string().email().parse(email);
      return this.sanitizeString(validEmail).toLowerCase();
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ValidationError(error);
      }
      throw error;
    }
  }

  /**
   * Check if data size is within limits
   */
  static validateDataSize(data: string | Uint8Array, maxSize: number): void {
    const size = typeof data === 'string' ? 
      new TextEncoder().encode(data).length : 
      data.length;

    if (size > maxSize) {
      throw new ValidationError(
        new z.ZodError([{
          code: 'too_big',
          maximum: maxSize,
          type: 'number',
          inclusive: true,
          message: `Data size ${size} exceeds maximum allowed size ${maxSize}`,
          path: ['dataSize']
        }])
      );
    }
  }
}

// Export validation error for use in other modules
export { z as ZodLib }; 