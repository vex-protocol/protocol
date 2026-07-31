/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

export type RegistryEvent =
    | {
          accountId: string;
          deviceKey: string;
          epoch: string;
          type: "device-added";
      }
    | {
          accountId: string;
          deviceKey: string;
          epoch: string;
          type: "device-revoked";
      }
    | {
          accountId: string;
          epoch: string;
          genesisDeviceKey: string;
          homeserverId: string;
          recoveryCommitment: string;
          type: "account-registered";
      }
    | {
          accountId: string;
          epoch: string;
          homeserverId: string;
          type: "homeserver-changed";
      }
    | {
          accountId: string;
          epoch: string;
          recoveryCommitment: string;
          type: "recovery-commitment-changed";
      }
    | {
          accountId: string;
          epoch: string;
          threshold: number;
          type: "device-threshold-changed";
      }
    | {
          accountId: string;
          nameHash: string;
          type: "username-registered";
          username: string;
      }
    | {
          endpoint: string;
          epoch: string;
          homeserverId: string;
          signingKey: string;
          type: "homeserver-registered";
      }
    | {
          endpoint: string;
          epoch: string;
          homeserverId: string;
          type: "homeserver-endpoint-changed";
      }
    | {
          epoch: string;
          homeserverId: string;
          signingKey: string;
          type: "homeserver-key-rotated";
      };
