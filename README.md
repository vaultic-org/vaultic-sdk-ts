# Vaultic SDK - Frontend End-to-End Encryption

[![npm version](https://badge.fury.io/js/@vaultic%2Fsdk.svg)](https://badge.fury.io/js/@vaultic%2Fsdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

🔐 **Enterprise-Grade Frontend E2E Encryption with Zero-Knowledge Security**

Vaultic SDK provides **secure cryptographic operations** for your frontend applications. Built for compliance, security, and scalability with mandatory server validation.

> 🏗️ **Architecture**: Frontend (@vaultic/sdk) handles crypto → Backend (@vaultic/identity) manages identities → Vaultic API validates everything

## Why Choose Vaultic SDK

### 🛡️ **Enterprise Security & Compliance**
- **Zero-knowledge encryption**: Your private keys never leave the client
- **Server-validated operations**: All crypto operations require server approval
- **Complete audit trail**: Full compliance reporting for regulations
- **Real-time monitoring**: Security analytics and threat detection

### ⚡ **Developer Experience**
- **Simple integration**: Get started in minutes with clear APIs
- **Multi-platform support**: React, Vue, Angular, React Native
- **TypeScript native**: Full type safety and autocomplete
- **Progressive examples**: From minimal to advanced use cases

### 📊 **Production Ready**
- **99.9% uptime SLA**: Reliable service you can depend on
- **Automatic scaling**: Handles your growth seamlessly
- **24/7 support**: Expert help when you need it

## Architecture Overview

```
Frontend (@vaultic/sdk) - THIS PACKAGE
┌─────────────────────┐    API Validation    ┌────────────────────────┐
│   Your Frontend     │ ──────────────────► │    Vaultic Platform    │
│   (React/Vue/etc)   │                      │                        │
│                     │                      │ • Validates All Ops    │
│ ┌─────────────────┐ │                      │ • Generates IDs        │
│ │ @vaultic/sdk    │ │ ◄──────────────── │ • Manages Quotas       │
│ │                 │ │   Signed Responses   │ • Enforces Permissions │
│ │ • Client Crypto │ │                      │ • Audit & Analytics    │
│ │ • Server Auth   │ │                      │ • Global CDN           │
│ └─────────────────┘ │                      └────────────────────────┘
└─────────────────────┘
          ▲
          │ HTTP API calls
          ▼
┌─────────────────────┐   Identity Creation  ┌─────────────────────┐
│   Your Backend      │ ◄─────────────────── │   Your Frontend     │
│   (Express/etc)     │                      │   (React/etc)       │
│                     │                      │                     │
│ ┌─────────────────┐ │                      │ ┌─────────────────┐ │
│ │ @vaultic/identity│ │                      │ │ User Registration│ │
│ │ (separate pkg)  │ │                      │ │ HTTP calls      │ │
│ │                 │ │                      │ └─────────────────┘ │
│ │ • createIdentity│ │                      └─────────────────────┘
│ │ • getPublicId   │ │
│ │ • User Management│ │
│ └─────────────────┘ │
└─────────────────────┘
```

## Quick Start

### 1. Get Your API Keys

Sign up at [dashboard.vaultic.app](https://dashboard.vaultic.app) to get your API keys.

### 2. Install Packages

**Frontend** (crypto operations):
```bash
npm install @vaultic/sdk
```

**Backend** (identity management):
```bash
npm install @vaultic/identity
```

### 3. Backend Setup (Identity Creation)

```typescript
// backend/auth.js - Your authentication endpoints
import { createIdentity, getPublicIdentity } from '@vaultic/identity';

// Registration: Backend creates Vaultic identity
app.post('/auth/register', async (req, res) => {
  const { email, password } = req.body;
  
  // 1. Create user in your database
  const user = await db.users.create({ email, password });
  
  // 2. Create Vaultic identity (backend only)
  const vaulticIdentity = await createIdentity(
    'your-app-id',
    'your-app-secret',  // Backend secret only
    user.id
  );
  
  // 3. Return public identity to frontend
  res.json({
    userId: user.id,
    vaulticIdentity: getPublicIdentity(vaulticIdentity)
  });
});

// Login: Backend provides existing identity
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  // 1. Verify user credentials
  const user = await authenticateUser(email, password);
  
  // 2. Get stored Vaultic identity
  const identity = await db.vaulticIdentities.findOne({ userId: user.id });
  
  // 3. Return public identity to frontend
  res.json({
    userId: user.id,
    vaulticIdentity: getPublicIdentity(identity.vaulticIdentity)
  });
});
```

### 4. Frontend Setup (Crypto Operations)

```typescript
// frontend/messaging.js - Your app logic
import { VaulticClient } from '@vaultic/sdk';

const vaultic = new VaulticClient({
  appId: 'your-app-id',
  apiKey: 'vlt_your_api_key'
});

class SecureMessaging {
  async registerUser(email: string, password: string) {
    // 1. Call YOUR backend to create identity
    const response = await fetch('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    });
    
    const { userId, vaulticIdentity } = await response.json();
    
    // 2. Initialize SDK with backend-created identity
    await vaultic.initialize();
    await vaultic.start(userId);
    await vaultic.registerIdentity({
      passphrase: password,
      identity: vaulticIdentity  // From backend
    });
    
    return userId;
  }

  async sendMessage(recipient: string, message: string) {
    // Frontend handles encryption (server validates)
    const encrypted = await vaultic.encrypt(message, {
      shareWithUsers: [recipient]
    });
    
    // Send encrypted data via your API
    await fetch('/api/messages', {
      method: 'POST',
      body: JSON.stringify({ recipient, encrypted })
    });
  }

  async receiveMessages() {
    // Get encrypted messages from your API
    const messages = await fetch('/api/messages').then(r => r.json());
    
    // Decrypt on frontend
    return Promise.all(messages.map(async msg => ({
      ...msg,
      content: await vaultic.decrypt(msg.encrypted)
    })));
  }
}
```

## Core Features

### 🔐 **Zero-Knowledge Cryptography**
- **Client-side encryption**: Data encrypted on device before transmission
- **Private keys stay local**: Generated and stored locally using WebCrypto
- **Server validates operations**: All crypto operations require server approval
- **Multi-device sync**: Seamless access across user devices

### 👤 **Identity Management** (via @vaultic/identity)
- **Backend-controlled identities**: `createIdentity(appId, appSecret, userId)`
- **Secure identity sharing**: `getPublicIdentity(identity)` for communication
- **User management**: Integrate with your existing auth system

### 🔒 **Group & Resource Management**
- **Server-generated IDs**: All group/resource IDs come from Vaultic servers
- **Permission validation**: Server checks access rights for all operations
- **Secure sharing**: Share encrypted data with users and groups

### ⚙️ **Server Validation Architecture**
- **Mandatory API connection**: All operations require server validation
- **Quota enforcement**: Server-side limits prevent abuse
- **Cryptographic signatures**: All server responses are signed
- **Anti-fork design**: SDK is useless without valid Vaultic API access

## Why This Architecture?

### ✅ **Security Benefits**
- **No offline vulnerabilities**: Can't bypass security without server
- **Audit compliance**: Complete trail of all operations
- **Access control**: Server validates every permission
- **Quota enforcement**: Prevents abuse and ensures billing accuracy

### ✅ **Business Benefits**
- **Revenue protection**: Impossible to bypass payment/limits
- **Usage tracking**: Accurate analytics and billing
- **Support enablement**: Full visibility for troubleshooting
- **Compliance ready**: SOC 2, GDPR, HIPAA documentation

### ✅ **Developer Benefits**
- **Simple integration**: Clear separation of concerns
- **Reliable operations**: Server validation prevents edge cases
- **Production ready**: Battle-tested with enterprise customers
- **Multi-platform**: Same API across all platforms

## Examples

### Minimal Example (10 lines)
```typescript
// 1. Authenticate with your backend
const { userId, identity } = await fetch('/api/auth/login', {
  method: 'POST', 
  body: JSON.stringify({ email, password })
}).then(r => r.json());

// 2. Setup SDK
const client = new VaulticClient({ appId, apiKey });
await client.initialize();
await client.start(userId);
await client.verifyIdentity({ type: 'passphrase', value: password, identity });

// 3. Encrypt/decrypt
const encrypted = await client.encrypt('secret', { shareWithUsers: ['user@example.com'] });
const decrypted = await client.decrypt(encrypted);
```

### Complete Integration
See [examples/basic-usage.ts](./examples/basic-usage.ts) for:
- User registration and login flows
- Secure messaging implementation
- Group management
- Error handling patterns
- Backend integration examples

## Error Handling

The SDK provides clear error codes for common scenarios:

```typescript
try {
  await vaultic.encrypt(data);
} catch (error) {
  if (error.code === 'API_CONNECTION_REQUIRED') {
    // Handle offline state
  } else if (error.code === 'QUOTA_EXCEEDED') {
    // Guide user to upgrade plan
  }
}
```

## Security Architecture

### 🔒 **Zero-Knowledge Design**
- Private keys generated locally using WebCrypto APIs
- All encryption happens client-side before API calls
- Vaultic servers never see plaintext data or private keys

### 🛡️ **Server Authority**
- All device/group/resource IDs generated server-side
- Every operation validated against server permissions
- Cryptographic signatures prevent tampering
- Continuous authentication via challenge-response

### ⚖️ **Compliance Ready**
- Complete audit trail for all operations
- SOC 2 Type II compliance with annual audits
- GDPR and HIPAA documentation available
- Real-time security monitoring

## Package Separation

### ✅ **@vaultic/sdk** (This Package)
- **Target**: Frontend applications
- **Purpose**: Cryptographic operations with server validation
- **Capabilities**: encrypt, decrypt, groups, sharing
- **Dependencies**: Native WebCrypto APIs only

### ✅ **@vaultic/identity** (Separate Package)
- **Target**: Backend applications only
- **Purpose**: Identity creation and management
- **Capabilities**: createIdentity, getPublicIdentity, user management
- **Security**: Requires app secret (backend only)

## Getting Started

1. **Sign up** at [dashboard.vaultic.app](https://dashboard.vaultic.app)
2. **Install packages**: `@vaultic/sdk` (frontend) + `@vaultic/identity` (backend)
3. **Set up backend** identity creation endpoints
4. **Integrate frontend** crypto operations
5. **Test and deploy** with confidence

## Documentation & Support

- 📖 [Complete Documentation](https://docs.vaultic.app)
- 🏗️ [Integration Examples](./examples/)
- 💬 [Discord Community](https://discord.gg/vaultic)
- 📧 [Email Support](mailto:support@vaultic.app)

---

**Build secure. Build with confidence. Build with Vaultic.** 

> ⚠️ **Security Notice**: This SDK requires active connection to Vaultic servers for all operations. The SDK is designed to be completely dependent on the Vaultic platform to ensure security, compliance, and proper usage tracking. 
