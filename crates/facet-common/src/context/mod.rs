//  Copyright (c) 2026 Metaform Systems, Inc
//
//  This program and the accompanying materials are made available under the
//  terms of the Apache License, Version 2.0 which is available at
//  https://www.apache.org/licenses/LICENSE-2.0
//
//  SPDX-License-Identifier: Apache-2.0
//
//  Contributors:
//       Metaform Systems, Inc. - initial API and implementation
//

use bon::Builder;

/// Participant data.
#[derive(Builder, Clone, Debug, PartialEq)]
pub struct ParticipantContext {
    // The internal participant context ID, a UUID.
    #[builder(into)]
    pub id: String,

    // The external participant context identifier, typically a Web DID.
    #[builder(into, default = "anonymous")]
    pub identifier: String,

    // The audience the context uses for validating tokens presented to it, typically the same as the identifier.
    #[builder(into, default = "anonymous")]
    pub audience: String,
}
