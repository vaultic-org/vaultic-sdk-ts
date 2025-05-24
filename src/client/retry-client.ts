// Retry Client - Handles network failures with exponential backoff
// Provides resilient API communication for production use

import { ApiClient } from './api-client';
import { VaulticConfig } from '../types';
import { ApiConnectionRequiredError } from '../errors';

interface RetryOptions {
  maxRetries: number;
  baseDelay: number;
  maxDelay: number;
  backoffMultiplier: number;
  retryableStatusCodes: number[];
}

export interface ConnectionState {
  isConnected: boolean;
  lastConnected: number;
  reconnectAttempts: number;
  isReconnecting: boolean;
}

export class RetryApiClient extends ApiClient {
  private retryOptions: RetryOptions;
  private connectionState: ConnectionState;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private onConnectionChange?: (state: ConnectionState) => void;

  constructor(config: VaulticConfig, retryOptions?: Partial<RetryOptions>) {
    super(config);
    
    this.retryOptions = {
      maxRetries: 3,
      baseDelay: 1000,
      maxDelay: 30000,
      backoffMultiplier: 2,
      retryableStatusCodes: [429, 500, 502, 503, 504],
      ...retryOptions
    };

    this.connectionState = {
      isConnected: false,
      lastConnected: 0,
      reconnectAttempts: 0,
      isReconnecting: false
    };
  }

  /**
   * Set callback for connection state changes
   */
  setConnectionChangeCallback(callback: (state: ConnectionState) => void): void {
    this.onConnectionChange = callback;
  }

    /**   * Initialize with automatic reconnection   */  override async initialize(): Promise<void> {
    try {
      await super.initialize();
      this.updateConnectionState(true);
    } catch (error) {
      this.updateConnectionState(false);
      await this.startReconnectionProcess();
      throw error;
    }
  }

  /**
   * Make request with retry logic and connection recovery
   */
  protected async makeRequestWithRetry<T = any>(
    method: string,
    endpoint: string,
    options: {
      body?: any;
      headers?: Record<string, string>;
    }
  ): Promise<T> {
    let lastError: Error;

    for (let attempt = 0; attempt <= this.retryOptions.maxRetries; attempt++) {
      try {
        // Check connection state before attempting request
        if (!this.connectionState.isConnected && !this.connectionState.isReconnecting) {
          await this.attemptReconnection();
        }

        const result = await this.makeBaseRequest<T>(method, endpoint, options);
        
        // Reset connection state on successful request
        if (!this.connectionState.isConnected) {
          this.updateConnectionState(true);
          this.stopReconnectionProcess();
        }

        return result;
      } catch (error) {
        lastError = error as Error;

        // Check if this is a retryable error
        if (!this.isRetryableError(error as Error) || attempt === this.retryOptions.maxRetries) {
          this.updateConnectionState(false);
          await this.startReconnectionProcess();
          throw error;
        }

        // Calculate delay with exponential backoff
        const delay = Math.min(
          this.retryOptions.baseDelay * Math.pow(this.retryOptions.backoffMultiplier, attempt),
          this.retryOptions.maxDelay
        );

        console.warn(
          `[VAULTIC SDK] Request failed (attempt ${attempt + 1}/${this.retryOptions.maxRetries + 1}). ` +
          `Retrying in ${delay}ms...`,
          error
        );

        await this.sleep(delay);
      }
    }

    this.updateConnectionState(false);
    await this.startReconnectionProcess();
    throw lastError!;
  }

  /**
   * Start automatic reconnection process
   */
  private async startReconnectionProcess(): Promise<void> {
    if (this.connectionState.isReconnecting) {
      return;
    }

    this.connectionState.isReconnecting = true;
    this.connectionState.reconnectAttempts = 0;

    console.warn('[VAULTIC SDK] Connection lost. Starting reconnection process...');

    this.scheduleReconnection();
  }

  /**
   * Stop reconnection process
   */
  private stopReconnectionProcess(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    this.connectionState.isReconnecting = false;
    this.connectionState.reconnectAttempts = 0;

    console.log('[VAULTIC SDK] Connection restored successfully');
  }

  /**
   * Schedule next reconnection attempt
   */
  private scheduleReconnection(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }

    const delay = Math.min(
      this.retryOptions.baseDelay * Math.pow(2, this.connectionState.reconnectAttempts),
      this.retryOptions.maxDelay
    );

    this.reconnectTimer = setTimeout(async () => {
      await this.attemptReconnection();
    }, delay);
  }

  /**
   * Attempt to reconnect to the API
   */
  private async attemptReconnection(): Promise<void> {
    this.connectionState.reconnectAttempts++;

    console.log(
      `[VAULTIC SDK] Reconnection attempt ${this.connectionState.reconnectAttempts}...`
    );

    try {
      await super.initialize();
      this.updateConnectionState(true);
      this.stopReconnectionProcess();
    } catch (error) {
      console.warn(
        `[VAULTIC SDK] Reconnection attempt ${this.connectionState.reconnectAttempts} failed:`,
        error
      );

      // Continue reconnection process if still needed
      if (this.connectionState.isReconnecting) {
        this.scheduleReconnection();
      }
    }
  }

  /**
   * Update connection state and notify listeners
   */
  private updateConnectionState(isConnected: boolean): void {
    const wasConnected = this.connectionState.isConnected;
    
    this.connectionState.isConnected = isConnected;
    
    if (isConnected) {
      this.connectionState.lastConnected = Date.now();
      this.connectionState.reconnectAttempts = 0;
    }

    // Notify listeners only if state actually changed
    if (wasConnected !== isConnected && this.onConnectionChange) {
      this.onConnectionChange({ ...this.connectionState });
    }
  }

  /**
   * Check if an error is retryable
   */
  private isRetryableError(error: Error): boolean {
    // Network errors are always retryable
    if (error instanceof TypeError && error.message.includes('fetch')) {
      return true;
    }

    // API connection errors are retryable
    if (error instanceof ApiConnectionRequiredError) {
      return true;
    }

    // Check HTTP status codes if available
    if ('status' in error) {
      return this.retryOptions.retryableStatusCodes.includes((error as any).status);
    }

    return false;
  }

  /**
   * Base request method (override from parent)
   */
  private async makeBaseRequest<T = any>(
    method: string,
    endpoint: string,
    options: {
      body?: any;
      headers?: Record<string, string>;
    }
  ): Promise<T> {
    // Call the parent's makeRequest method
    return (this as any).makeRequest(method, endpoint, options);
  }

  /**
   * Sleep utility for delays
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Get current connection state
   */
  getConnectionState(): ConnectionState {
    return { ...this.connectionState };
  }

  /**
   * Force reconnection attempt
   */
  async forceReconnect(): Promise<void> {
    this.stopReconnectionProcess();
    await this.attemptReconnection();
  }

  /**
   * Cleanup resources
   */
    destroy(): void {    this.stopReconnectionProcess();    this.onConnectionChange = undefined!;  }
} 