# Vaultic SDK - Security Architecture

## Overview

Vaultic provides **secure end-to-end encryption** through a carefully designed architecture that separates responsibilities between frontend and backend while ensuring all operations are validated by Vaultic servers.

**Key Principle**: Frontend handles crypto operations, Backend manages identities, Vaultic validates everything.

## Architecture Components

```
Your Application Architecture
┌─────────────────────────────┐
│         Frontend            │
│     (@vaultic/sdk)          │
│                             │
│  • Encrypts/decrypts data   │
│  • Manages local keys       │
│  • Validates with server    │
│  • Handles user interface   │
└─────────────┬───────────────┘
              │ HTTPS API calls
              ▼
┌─────────────────────────────┐
│         Your Backend        │
│    (@vaultic/identity)      │
│                             │
│  • Creates user accounts    │
│  • Creates Vaultic identities│
│  • Manages user sessions    │
│  • Stores encrypted data    │
└─────────────┬───────────────┘
              │ Server validation
              ▼
┌─────────────────────────────┐
│      Vaultic Platform       │
│                             │
│  • Validates all operations │
│  • Generates secure IDs     │
│  • Enforces quotas/limits   │
│  • Provides audit trails    │
│  • Signs all responses      │
└─────────────────────────────┘
```

## Package Responsibilities

### 🎨 **@vaultic/sdk** (Frontend Package)
**Purpose**: Handle cryptographic operations with server validation

**Core Features**:
- **Client-side encryption/decryption** using WebCrypto APIs
- **Server-validated operations** - every action requires server approval
- **Group and resource management** with server-generated IDs
- **Multi-device synchronization** through server coordination
- **Real-time status management** for user interface

**Key Principle**: All crypto happens locally, but server validates permissions.

### 🏗️ **@vaultic/identity** (Backend Package)
**Purpose**: Manage user identities and authentication

**Core Features**:
- **Identity creation**: `createIdentity(appId, appSecret, userId)`
- **Public identity sharing**: `getPublicIdentity(identity)`
- **User management** integration with your existing auth system
- **Secure credential storage** with app-level secrets

**Key Principle**: Only backend can create identities using app secrets.

### 🛡️ **Vaultic Platform** (SaaS Service)
**Purpose**: Validate, authorize, and audit all operations

**Core Features**:
- **Operation validation** - checks permissions for every action
- **ID generation** - all device/group/resource IDs come from server
- **Quota enforcement** - prevents abuse and enables billing
- **Cryptographic signatures** - signs all responses to prevent tampering
- **Audit logging** - complete trail for compliance

**Key Principle**: Nothing critical happens without server validation.

## Security Model

### 🔒 **Zero-Knowledge Cryptography**

**What stays on client**:
- Private keys (generated locally with WebCrypto)
- Plaintext data (encrypted before sending)
- Decryption operations (happens locally)

**What goes to server**:
- Encrypted data only
- Public keys for sharing
- Operation requests for validation
- Usage analytics (no sensitive data)

**Result**: Vaultic never sees your plaintext data or private keys.

### 🛡️ **Server Authority Model**

**Server controls**:
- Device registration and IDs
- Group creation and management
- Resource access permissions
- Quota and rate limiting
- Billing and usage tracking

**Client controls**:
- Local key generation
- Data encryption/decryption
- User interface and experience

**Result**: Strong security with server oversight, but zero-knowledge privacy.

## Authentication Flow

### 1. **Identity Creation** (Backend → Vaultic)
```typescript
// Your backend creates identity
const identity = await createIdentity(appId, appSecret, userId);

// Store in your database
await db.users.update(userId, { 
  vaulticIdentity: identity 
});

// Return public info to frontend
return getPublicIdentity(identity);
```

### 2. **User Registration** (Frontend → Backend → Vaultic)
```typescript
// Frontend calls your backend
const response = await fetch('/api/auth/register', {
  body: JSON.stringify({ email, password })
});

const { userId, vaulticIdentity } = await response.json();

// Frontend uses backend-created identity
await vaultic.registerIdentity({
  passphrase: password,
  identity: vaulticIdentity  // From backend
});
```

### 3. **Session Authentication** (Frontend ↔ Vaultic)
```typescript
// SDK requests challenge from Vaultic
const challenge = await apiClient.requestChallenge();

// Signs challenge with local private key
const signature = await signChallenge(challenge, privateKey);

// Vaultic validates and returns session token
const session = await apiClient.authenticate(challenge.id, signature);
```

## Operation Validation

### **Encryption Flow**
```
1. User wants to encrypt data
2. Frontend → Vaultic: "Can I encrypt X bytes for users Y?"
3. Vaultic checks: quota, permissions, user validity
4. Vaultic → Frontend: "Yes, here's resource ID"
5. Frontend encrypts data locally
6. Frontend stores encrypted data in your backend
7. Vaultic tracks resource for quotas/billing
```

### **Decryption Flow**
```
1. User wants to decrypt data
2. Frontend extracts resource ID from encrypted data
3. Frontend → Vaultic: "Can I decrypt resource X?"
4. Vaultic checks: user access, resource validity
5. Vaultic → Frontend: "Yes, here's the decryption key"
6. Frontend decrypts data locally
```

### **Group Management Flow**
```
1. User wants to create group
2. Frontend → Vaultic: "Create group with members X, Y, Z"
3. Vaultic validates: user permissions, member existence
4. Vaultic creates group with server-generated ID
5. Vaultic → Frontend: "Group created, ID = group_abc123"
6. Frontend can now encrypt for this group
```

## Data Flow Examples

### **Secure Messaging Application**

```typescript
// 1. User registration (Backend creates identity)
POST /api/auth/register { email, password }
├─ Backend: createIdentity(appId, appSecret, user.id)
├─ Backend: Store identity in database
└─ Response: { userId, vaulticIdentity }

// 2. Frontend setup (SDK uses identity)
const vaultic = new VaulticClient({ appId, apiKey });
await vaultic.initialize();  // ← Validates with Vaultic
await vaultic.start(userId);
await vaultic.registerIdentity({ 
  passphrase: password, 
  identity: vaulticIdentity  // ← From backend
});

// 3. Send message (Client encrypts, server validates)
const encrypted = await vaultic.encrypt(message, {
  shareWithUsers: ['recipient@example.com']
});
├─ Vaultic validates: quota, permissions, recipients
├─ Client encrypts data locally
└─ Store encrypted data in your backend

// 4. Receive message (Server validates, client decrypts)
const messages = await fetchFromBackend('/api/messages');
for (const msg of messages) {
  const decrypted = await vaultic.decrypt(msg.encrypted);
  ├─ Vaultic validates: user access to resource
  └─ Client decrypts data locally
}
```

## Compliance & Security Benefits

### **Audit Trail**
- Complete log of all operations on Vaultic servers
- User actions, timestamps, and outcomes recorded
- Compliance-ready reports for SOC 2, GDPR, HIPAA

### **Access Control**
- Server validates every permission before operation
- Group membership enforced server-side
- Resource access controlled by Vaultic platform

### **Usage Monitoring**
- Real-time tracking of encryption/decryption operations
- Quota management and billing accuracy
- Abuse prevention and rate limiting

### **Incident Response**
- Immediate visibility into security events
- Device revocation and user blocking capabilities
- Complete audit trail for forensic analysis

## Integration Patterns

### **Web Applications**
```typescript
// Frontend: React/Vue/Angular with @vaultic/sdk
// Backend: Node.js/Python/etc with @vaultic/identity
// Communication: Standard HTTPS APIs between frontend/backend
```

### **Mobile Applications**
```typescript
// Mobile: React Native/Flutter with @vaultic/sdk
// Backend: Same as web - @vaultic/identity
// Communication: Same APIs work across platforms
```

### **Existing Applications**
```typescript
// Add encryption to existing app:
// 1. Install @vaultic/identity in existing backend
// 2. Add identity creation to registration flow
// 3. Install @vaultic/sdk in existing frontend  
// 4. Add encryption to sensitive operations
```

## Production Considerations

### **Performance**
- Client-side crypto operations are fast (native WebCrypto)
- Server validation adds minimal latency (~50-100ms)
- CDN ensures global availability with low latency

### **Scalability**
- Server validation scales automatically
- Client-side crypto scales with user devices
- No server-side crypto bottlenecks

### **Reliability**
- 99.9% uptime SLA for Vaultic platform
- Graceful degradation when validation is slow
- Automatic retry and reconnection logic

### **Security**
- Regular security audits and penetration testing
- SOC 2 Type II certification
- 24/7 security monitoring and incident response

---

This architecture provides **maximum security** through server validation while maintaining **zero-knowledge privacy** through client-side cryptography.