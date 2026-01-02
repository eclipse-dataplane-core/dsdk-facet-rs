# facet-rs

A Rust library providing feature building blocks for use with
the [Eclipse Rust Data Plane SDK](https://github.com/eclipse-dataplane-core/dataplane-sdk-rust).

## Overview

**facet-rs** includes components for the following features:

### Distributed Locking

Coordinate exclusive access to shared resources across multiple services or instances using a pluggable lock manager.
Features include:

- Reentrant locking 
- Automatic expiration of stale locks to prevent deadlocks
- Multiple implementations (in-memory for testing, PostgreSQL for production)

### Token Management

Manage OAuth/JWT token lifecycles with automatic refresh and concurrency control:

- Automatic refresh of expiring tokens 
- Distributed coordination to prevent concurrent refresh attempts
- Pluggable token storage and client implementations
- Built-in support for in-memory and persistent storage backends

