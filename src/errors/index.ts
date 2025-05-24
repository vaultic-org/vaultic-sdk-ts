// Error system that enforces API dependency and prevents offline usage

export class VaulticError extends Error {
  public readonly code: string;
  public readonly details?: any;

  constructor(code: string, message: string, details?: any) {
    super(message);
    this.name = 'VaulticError';
    this.code = code;
    this.details = details;
  }
}

// Critical errors that prevent SDK functionality without API
export class ApiConnectionRequiredError extends VaulticError {
  constructor(operation: string) {
    super(
      'API_CONNECTION_REQUIRED',
      `Operation "${operation}" requires active connection to Vaultic API. ` +
      'This SDK cannot function without server validation.',
      { operation }
    );
  }
}

export class ServerValidationRequiredError extends VaulticError {
  constructor(resource: string) {
    super(
      'SERVER_VALIDATION_REQUIRED',
      `Resource "${resource}" requires server validation. ` +
      'Local operations are not permitted for security reasons.',
      { resource }
    );
  }
}

export class InvalidServerSignatureError extends VaulticError {
  constructor(resource: string) {
    super(
      'INVALID_SERVER_SIGNATURE',
      `Server signature validation failed for "${resource}". ` +
      'This may indicate tampering or unauthorized access.',
      { resource }
    );
  }
}

export class AuthenticationRequiredError extends VaulticError {
  constructor() {
    super(
      'AUTHENTICATION_REQUIRED',
      'Operation requires valid authentication token from Vaultic API. ' +
      'Please authenticate before proceeding.'
    );
  }
}

export class DeviceNotRegisteredError extends VaulticError {
  constructor() {
    super(
      'DEVICE_NOT_REGISTERED',
      'Device must be registered with Vaultic API before use. ' +
      'Local device creation is not permitted.'
    );
  }
}

export class GroupNotFoundError extends VaulticError {
  constructor(groupId: string) {
    super(
      'GROUP_NOT_FOUND',
      `Group "${groupId}" not found in server registry. ` +
      'Local group creation is not supported.',
      { groupId }
    );
  }
}

export class ResourceNotFoundError extends VaulticError {
  constructor(resourceId: string) {
    super(
      'RESOURCE_NOT_FOUND',
      `Resource "${resourceId}" not found in server registry. ` +
      'Local resource management is not supported.',
      { resourceId }
    );
  }
}

export class QuotaExceededError extends VaulticError {
  constructor(operation: string, limit: number) {
    super(
      'QUOTA_EXCEEDED',
      `Quota exceeded for operation "${operation}". Limit: ${limit}. ` +
      'Please upgrade your plan or contact support.',
      { operation, limit }
    );
  }
}

export class InvalidApiKeyError extends VaulticError {
  constructor() {
    super(
      'INVALID_API_KEY',
      'Invalid API key provided. Please check your credentials.'
    );
  }
}

export class ChallengeExpiredError extends VaulticError {
  constructor() {
    super(
      'CHALLENGE_EXPIRED',
      'Authentication challenge has expired. Please request a new one.'
    );
  }
}

export class ForkDetectedError extends VaulticError {
  constructor() {
    super(
      'FORK_DETECTED',
      'Unauthorized SDK modification detected. ' +
      'This SDK requires official Vaultic API validation for all operations.'
    );
  }
}

// Utility function to enforce API dependency
export function requireApiConnection(operation: string): never {
  throw new ApiConnectionRequiredError(operation);
}

export function requireServerValidation(resource: string): never {
  throw new ServerValidationRequiredError(resource);
}

export function throwIfOffline(operation: string, isConnected: boolean): void {
  if (!isConnected) {
    throw new ApiConnectionRequiredError(operation);
  }
}

// Error codes enum for easy reference
export enum ErrorCodes {
  API_CONNECTION_REQUIRED = 'API_CONNECTION_REQUIRED',
  SERVER_VALIDATION_REQUIRED = 'SERVER_VALIDATION_REQUIRED',
  INVALID_SERVER_SIGNATURE = 'INVALID_SERVER_SIGNATURE',
  AUTHENTICATION_REQUIRED = 'AUTHENTICATION_REQUIRED',
  DEVICE_NOT_REGISTERED = 'DEVICE_NOT_REGISTERED',
  GROUP_NOT_FOUND = 'GROUP_NOT_FOUND',
  RESOURCE_NOT_FOUND = 'RESOURCE_NOT_FOUND',
  QUOTA_EXCEEDED = 'QUOTA_EXCEEDED',
  INVALID_API_KEY = 'INVALID_API_KEY',
  CHALLENGE_EXPIRED = 'CHALLENGE_EXPIRED',
  FORK_DETECTED = 'FORK_DETECTED'
} 