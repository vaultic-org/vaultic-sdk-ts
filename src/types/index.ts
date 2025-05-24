// Types for API communication and core SDK structures

export interface VaulticConfig {
  appId: string;
  apiKey: string;
  apiUrl?: string;
  crypto?: CryptoConfig;
}

export interface CryptoConfig {
  defaultAlgorithm?: CryptoAlgorithm;
}

export enum CryptoAlgorithm {
  RSA_2048 = 'rsa_2048',
  ECC_P256 = 'ecc_p256'
}

export enum Status {
  STOPPED = 'STOPPED',
  STARTING = 'STARTING',
  IDENTITY_REGISTRATION_NEEDED = 'IDENTITY_REGISTRATION_NEEDED',
  IDENTITY_VERIFICATION_NEEDED = 'IDENTITY_VERIFICATION_NEEDED',
  READY = 'READY'
}

// API Response types - all critical data comes from server
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  timestamp: number;
  signature: string; // Server signature to prevent tampering
}

export interface Challenge {
  challengeId: string;
  challenge: string;
  expiresAt: number;
  signature: string; // Server signed challenge
}

export interface AuthenticationToken {
  token: string;
  deviceId: string;
  userId: string;
  expiresAt: number;
  signature: string; // Server signed token
}

// Device management - all IDs generated server-side
export interface Device {
  deviceId: string;
  userId: string;
  publicSignatureKey: string;
  publicEncryptionKey: string;
  createdAt: number;
  lastSeen: number;
  isRevoked: boolean;
  revokedAt?: number;
  serverSignature: string; // Prevents local device creation
}

export interface DeviceKeys {
  signatureKeyPair: CryptoKeyPair;
  encryptionKeyPair: CryptoKeyPair;
}

// Identity and verification - server controlled
export interface Identity {
  userId: string;
  status: Status;
  devices: Device[];
  publicIdentity: string;
  serverSignature: string;
}

export interface VerificationMethod {
  type: 'passphrase' | 'verificationKey' | 'email' | 'phoneNumber';
  value?: string;
  identity?: any; // Backend-provided identity from @vaultic/identity
}

export interface Registration {
  passphrase?: string;
  verificationKey?: string;
  enableMultiDevice?: boolean;
  identity?: any; // Backend-provided identity from @vaultic/identity
}

// Group management - all server controlled
export interface Group {
  groupId: string;
  publicEncryptionKey: string;
  members: string[];
  provisionalMembers: ProvisionalMember[];
  createdAt: number;
  lastModified: number;
  isInternal: boolean;
  serverSignature: string; // Prevents local group manipulation
}

export interface ProvisionalMember {
  appSignaturePublicKey: string;
  vaulticSignaturePublicKey: string;
  appEncryptionPublicKey: string;
  vaulticEncryptionPublicKey: string;
}

// Resource management - server authoritative
export interface Resource {
  resourceId: string;
  encryptionKey: string;
  createdAt: number;
  sharedWith: string[];
  groups: string[];
  serverSignature: string;
}

export interface EncryptionOptions {
  shareWithUsers?: string[];
  shareWithGroups?: string[];
  paddingStep?: number;
}

export interface DecryptionOptions {
  outputFormat?: 'string' | 'uint8array';
}

// Error types
export interface VaulticError extends Error {
  code: string;
  details?: any;
}

// Events
export interface StatusChangeEvent {
  previousStatus: Status;
  status: Status;
  timestamp: number;
}

export interface ProgressEvent {
  currentBytes: number;
  totalBytes: number;
  percentage: number;
}

// Storage interfaces - local cache only, server is source of truth
export interface LocalData {
  deviceKeys?: DeviceKeys;
  userSecret?: Uint8Array;
  lastSyncTimestamp: number;
  serverSignature: string; // Validates local cache integrity
}

export interface KeyStore {
  save(data: LocalData, userSecret: Uint8Array): Promise<void>;
  load(userSecret: Uint8Array): Promise<LocalData | null>;
  clear(): Promise<void>;
}

export interface ResourceStore {
  saveResourceKey(resourceId: string, key: string): Promise<void>;
  findResourceKey(resourceId: string): Promise<string | null>;
  clear(): Promise<void>;
}

export interface GroupStore {
  saveGroup(group: Group): Promise<void>;
  findGroup(groupId: string): Promise<Group | null>;
  clear(): Promise<void>;
}

// API endpoints structure
export interface ApiEndpoints {
  challenges: string;
  authentication: string;
  devices: string;
  users: string;
  groups: string;
  resources: string;
  encryption: string;
  decryption: string;
  sharing: string;
}

// Advanced encryption options
export interface StreamEncryptionOptions extends EncryptionOptions {
  onProgress?: (progress: ProgressEvent) => void;
  maxChunkSize?: number;
}

export interface EncryptionSession {
  resourceId: string;
  encrypt(data: string | Uint8Array): Promise<Uint8Array>;
  encryptData(data: Uint8Array): Promise<Uint8Array>;
}

// Encryption formats and metadata
export interface EncryptionFormat {
  version: number;
  algorithm: string;
  chunkSize?: number;
}

export interface ResourceMetadata {
  name?: string;
  type?: string;
  lastModified?: number;
}

// Advanced sharing options
export interface SharingOptions {
  shareWithUsers?: string[];
  shareWithGroups?: string[];
  shareWithProvisionalUsers?: string[];
}

// Verification key types
export interface VerificationKey {
  privateKey: string;
  publicKey: string;
}

// Stream interfaces
export interface EncryptionStream {
  resourceId: string;
  write(chunk: Uint8Array): void;
  end(): Promise<void>;
  on(event: string, callback: Function): void;
}

export interface DecryptionStream {
  metadata?: ResourceMetadata;
  read(): Uint8Array | null;
  on(event: string, callback: Function): void;
}

// Identity types - detailed structure
export interface PrivateIdentity {
  userId: string;
  userSecret: Uint8Array;
  deviceKeys: DeviceKeys;
  appId: string;
  trustchainId: string;
  trustchainPublicKey: string;
}

export interface PublicIdentity {
  userId: string;
  appId: string;
  trustchainId: string;
  trustchainPublicKey: string;
  publicSignatureKey: string;
  publicEncryptionKey: string;
}

export interface ProvisionalIdentity {
  value: string; // email or phone
  appId: string;
  appPublicSignatureKey: string;
  appEncryptionKeyPair: CryptoKeyPair;
  vaulticPublicSignatureKey: string;
  vaulticEncryptionKeyPair: CryptoKeyPair;
}

// Cryptographic algorithms configuration
export interface CryptoSettings {
  signatureAlgorithm: 'ECDSA'; // P-256 curve
  encryptionAlgorithm: 'ECDH';  // P-256 curve  
  symmetricAlgorithm: 'AES-GCM'; // 256-bit
  hashAlgorithm: 'SHA-256';
  keyDerivation: 'PBKDF2';
} 