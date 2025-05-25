/**
 * Simple EventEmitter implementation for browser compatibility
 * Replaces Node.js 'events' module dependency
 */

type EventListener = (...args: unknown[]) => void;

export class EventEmitter {
    private events: Map<string, EventListener[]> = new Map();

    /**
     * Add a listener for the specified event
     */
    on(event: string, listener: EventListener): this {
        if (!this.events.has(event)) {
            this.events.set(event, []);
        }
        this.events.get(event)!.push(listener);
        return this;
    }

    /**
     * Add a one-time listener for the specified event
     */
    once(event: string, listener: EventListener): this {
        const onceWrapper = (...args: unknown[]) => {
            this.off(event, onceWrapper);
            listener.apply(this, args);
        };
        return this.on(event, onceWrapper);
    }

    /**
     * Remove a listener for the specified event
     */
    off(event: string, listener: EventListener): this {
        const listeners = this.events.get(event);
        if (listeners) {
            const index = listeners.indexOf(listener);
            if (index !== -1) {
                listeners.splice(index, 1);
            }
            if (listeners.length === 0) {
                this.events.delete(event);
            }
        }
        return this;
    }

    /**
     * Remove all listeners for the specified event, or all events if no event specified
     */
    removeAllListeners(event?: string): this {
        if (event) {
            this.events.delete(event);
        } else {
            this.events.clear();
        }
        return this;
    }

    /**
     * Emit an event with the specified arguments
     */
    emit(event: string, ...args: unknown[]): boolean {
        const listeners = this.events.get(event);
        if (listeners && listeners.length > 0) {
            listeners.forEach(listener => {
                try {
                    listener.apply(this, args);
                } catch (error) {
                    console.error(`Error in event listener for '${event}':`, error);
                }
            });
            return true;
        }
        return false;
    }

    /**
     * Get the number of listeners for the specified event
     */
    listenerCount(event: string): number {
        const listeners = this.events.get(event);
        return listeners ? listeners.length : 0;
    }

    /**
     * Get all listeners for the specified event
     */
    listeners(event: string): EventListener[] {
        const listeners = this.events.get(event);
        return listeners ? [...listeners] : [];
    }

    /**
     * Get all event names that have listeners
     */
    eventNames(): string[] {
        return Array.from(this.events.keys());
    }
} 