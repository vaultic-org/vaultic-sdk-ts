/**
 * Vaultic SDK Usage Guide - Simple Encrypted Messaging
 * 
 * This guide shows the correct architecture:
 * - Backend (@vaultic/identity) creates identities
 * - Frontend (@vaultic/sdk) uses identities for crypto operations
 */
import { VaulticClient } from '../src/index';

// 📋 STEP 1: Initial Configuration
const vaultic = new VaulticClient({
    appId: 'my-app',                                // Your application ID
    apiKey: 'vlt_your_key_from_dashboard'          // API key from dashboard.vaultic.app
});

/**
 * 🚀 Main class for secure messaging
 * Shows correct architecture: Backend creates identity, Frontend uses it
 */
export class SecureMessaging {
    private vaultic: VaulticClient;

    constructor() {
        this.vaultic = vaultic;
        this.setupEventListeners();
    }

    // 📡 Setup status event listeners
    private setupEventListeners() {
        this.vaultic.on('statusChange', (event) => {
            switch (event.status) {
                case 'IDENTITY_REGISTRATION_NEEDED':
                    console.log('✍️ Registration needed - backend must create identity');
                    break;
                case 'IDENTITY_VERIFICATION_NEEDED':
                    console.log('🔐 Login needed - verify with backend identity');
                    break;
                case 'READY':
                    console.log('✅ Ready - encryption available');
                    break;
            }
        });
    }

    /**
     * 🎯 STEP 2: Start user session
     */
    async startSession(userId: string) {
        // Mandatory initialization with server validation
        await this.vaultic.initialize();

        // Start session for this user
        await this.vaultic.start(userId);

        console.log(`Session started for: ${userId}`);
    }

    /**
     * 👤 STEP 3a: Register new user (BACKEND CREATES IDENTITY)
     * Frontend calls backend, backend uses @vaultic/identity
     */
    async registerUser(email: string, password: string) {
        // 1. Call YOUR backend to create user account + Vaultic identity
        const response = await this.sendToBackend('/auth/register', {
            email,
            password
        });
        
        // 2. Backend response contains identity created by @vaultic/identity
        const { userId, vaulticIdentity } = response;
        
        // 3. Frontend SDK uses the backend-created identity
        const identity = await this.vaultic.registerIdentity({
            passphrase: password,
            enableMultiDevice: true,
            // Identity data comes from backend (@vaultic/identity)
            identity: vaulticIdentity
        });
        
        console.log('User registered successfully via backend');
        return { userId, identity };
    }

    /**
     * 🔓 STEP 3b: Login existing user (BACKEND VERIFIES IDENTITY)
     * Frontend verifies with backend, then authenticates SDK
     */
    async loginUser(email: string, password: string) {
        // 1. Authenticate with YOUR backend first
        const response = await this.sendToBackend('/auth/login', {
            email,
            password
        });
        
        // 2. Backend validates and returns identity info
        const { userId, vaulticIdentity } = response;
        
        // 3. Use backend-provided identity to verify with SDK
        await this.vaultic.verifyIdentity({
            type: 'passphrase',
            value: password,
            // Identity verification data from backend
            identity: vaulticIdentity
        });
        
        console.log('User logged in successfully via backend');
        return userId;
    }

    /**
     * 💬 STEP 4: Send encrypted message
     */
    async sendMessage(recipient: string, message: string) {
        // Automatic encryption for recipient
        const encryptedMessage = await this.vaultic.encrypt(message, {
            shareWithUsers: [recipient]
        });
        
        // Send to your backend (replace with your API)
        await this.sendToBackend('/messages', {
            recipient,
            content: Array.from(encryptedMessage),
            timestamp: Date.now()
        });
        
        console.log('Message sent securely');
    }

    /**
     * 📨 STEP 5: Receive and decrypt messages
     */
    async receiveMessages() {
        // Fetch from your backend
        const messages = await this.fetchFromBackend('/messages');
        
        // Decrypt each message
        const decryptedMessages: Array<{ content: string | Uint8Array; [key: string]: any }> = [];
        for (const msg of messages) {
            try {
                const encryptedContent = new Uint8Array(msg.content);
                const decryptedContent = await this.vaultic.decrypt(encryptedContent);
                
                decryptedMessages.push({
                    ...msg,
                    content: decryptedContent
                });
            } catch (error) {
                console.warn('Unable to decrypt a message');
            }
        }
        
        return decryptedMessages;
    }

    /**
     * 👥 STEP 6: Create secure group
     */
    async createGroup(members: string[]) {
        const groupId = await this.vaultic.createGroup(members);
        
        console.log(`Group created: ${groupId}`);
        return groupId;
    }

    /**
     * 📤 STEP 7: Send group message
     */
    async sendGroupMessage(groupId: string, message: string) {
        const encryptedMessage = await this.vaultic.encrypt(message, {
            shareWithGroups: [groupId]
        });
        
        await this.sendToBackend('/group-messages', {
            groupId,
            content: Array.from(encryptedMessage),
            timestamp: Date.now()
        });
        
        console.log('Group message sent');
    }

    /**
     * 🚪 Clean logout
     */
    async logout() {
        await this.vaultic.stop();
        console.log('Logout completed');
    }

    // 🔧 Backend utility methods
    private async sendToBackend(endpoint: string, data: Record<string, unknown>) {
        const response = await fetch(`/api${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        
        if (!response.ok) {
            throw new Error(`Backend error: ${response.status}`);
        }
        
        return response.json();
    }

    private async fetchFromBackend(endpoint: string): Promise<any[]> {
        const response = await fetch(`/api${endpoint}`);
        
        if (!response.ok) {
            throw new Error(`Backend error: ${response.status}`);
        }
        
        return response.json();
    }
}

/**
 * 🎮 COMPLETE USAGE EXAMPLE
 * Shows correct architecture with backend identity management
 */
export async function completeExample() {
    const messaging = new SecureMessaging();
    
    try {
        // 1. Register new user (backend creates identity)
        // const { userId } = await messaging.registerUser('alice@example.com', 'strong-password');
        
        // 2. OR Login existing user (backend verifies identity)
        // const userId = await messaging.loginUser('alice@example.com', 'strong-password');
        
        // 3. Start SDK session with user ID from backend
        // await messaging.startSession(userId);
        
        // 4. Send private message
        // await messaging.sendMessage('bob@example.com', 'Hello Bob!');
        
        // 5. Create group
        // const groupId = await messaging.createGroup(['bob@example.com', 'charlie@example.com']);
        
        // 6. Send group message
        // await messaging.sendGroupMessage(groupId, 'Hello everyone!');
        
        // 7. Read messages
        // const messages = await messaging.receiveMessages();
        // console.log('Received messages:', messages);
        
        console.log('✅ Example completed successfully');
        
    } catch (error) {
        console.error('❌ Error:', error);
    }
}

/**
 * 📚 MINIMAL EXAMPLE - CORRECT ARCHITECTURE
 * Backend creates identity, frontend uses it
 */
export async function minimalExample() {
    // 1. Call your backend to create/verify user + identity
    const authResponse = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            email: 'user@example.com',
            password: 'password'
        })
    });
    
    const { userId, vaulticIdentity } = await authResponse.json();
    
    // 2. Configure SDK
    const client = new VaulticClient({
        appId: 'my-app',
        apiKey: 'vlt_my_key'
    });

    // 3. Initialize and start session
    await client.initialize();
    await client.start(userId);
    
    // 4. Verify with backend-provided identity
    await client.verifyIdentity({
        type: 'passphrase',
        value: 'password',
        identity: vaulticIdentity
    });
    
    // 5. Now you can encrypt/decrypt
    const encryptedMessage = await client.encrypt('Secret message', {
        shareWithUsers: ['recipient@example.com']
    });
    
    const decryptedMessage = await client.decrypt(encryptedMessage);
    console.log('Decrypted message:', decryptedMessage);
}

/**
 * 🏗️ BACKEND EXAMPLE (Node.js with @vaultic/identity)
 * This shows what your backend should do
 */
export const backendExample = `
// Backend code (Node.js + @vaultic/identity)
import { createIdentity, getPublicIdentity } from '@vaultic/identity';

// Registration endpoint
app.post('/auth/register', async (req, res) => {
    const { email, password } = req.body;
    
    // 1. Create user in your database
    const user = await db.users.create({ email, password });
    
    // 2. Create Vaultic identity (BACKEND RESPONSIBILITY)
    const vaulticIdentity = await createIdentity(
        'your-app-id',
        'your-app-secret',  // Backend secret only
        user.id
    );
    
    // 3. Store identity link in your database
    await db.vaulticIdentities.create({
        userId: user.id,
        vaulticIdentity: vaulticIdentity
    });
    
    // 4. Return user info + identity to frontend
    res.json({
        userId: user.id,
        vaulticIdentity: getPublicIdentity(vaulticIdentity)
    });
});

// Login endpoint
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;
    
    // 1. Verify user credentials
    const user = await db.users.findOne({ email });
    if (!user || !verifyPassword(password, user.password)) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // 2. Get stored Vaultic identity
    const identity = await db.vaulticIdentities.findOne({ userId: user.id });
    
    // 3. Return user info + identity to frontend
    res.json({
        userId: user.id,
        vaulticIdentity: getPublicIdentity(identity.vaulticIdentity)
    });
});
`;

/**
 * 🔍 SIMPLE ERROR HANDLING
 */
export async function errorHandling() {
    try {
        // First authenticate with your backend
        const authResponse = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: 'user@example.com', password: 'password' })
        });
        
        if (!authResponse.ok) {
            throw new Error('Backend authentication failed');
        }
        
        const { userId, vaulticIdentity } = await authResponse.json();
        
        // Then initialize SDK
        const client = new VaulticClient({
            appId: 'my-app',
            apiKey: 'vlt_my_key'
        });
        
        await client.initialize();
        await client.start(userId);
        
    } catch (error) {
        const vaulticError = error as { code?: string; message?: string };
        
        if (vaulticError.message?.includes('Backend')) {
            console.log('Backend authentication error');
        } else if (vaulticError.code === 'API_CONNECTION_REQUIRED') {
            console.log('No internet connection');
        } else if (vaulticError.code === 'INVALID_API_KEY') {
            console.log('Invalid API key');
        } else {
            console.log('Other error:', vaulticError.message || 'Unknown error');
        }
    }
} 