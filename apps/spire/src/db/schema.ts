/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { Insertable, Selectable, Updateable } from "kysely";

// ── Table interfaces ────────────────────────────────────────────────────

export type AccountEntitlementRow = Selectable<AccountEntitlementsTable>;

export interface AccountEntitlementsTable {
    expiresAt: null | string;
    source: string;
    tier: string;
    updatedAt: string;
    userID: string;
}

export type AccountEntitlementUpdate = Updateable<AccountEntitlementsTable>;

export type BillingStoreSubscriptionRow =
    Selectable<BillingStoreSubscriptionsTable>;

export interface BillingStoreSubscriptionsTable {
    createdAt: string;
    environment: string;
    expiresAt: null | string;
    externalOriginalID: null | string;
    externalTransactionID: null | string;
    platform: string;
    productID: string;
    purchaseToken: null | string;
    purchaseTokenHash: null | string;
    rawPayload: string;
    status: string;
    storeProductID: string;
    subscriptionID: string;
    tier: string;
    updatedAt: string;
    userID: string;
}

export type BillingStoreSubscriptionUpdate =
    Updateable<BillingStoreSubscriptionsTable>;

export type BillingStoreTransactionRow =
    Selectable<BillingStoreTransactionsTable>;

export interface BillingStoreTransactionsTable {
    environment: string;
    eventType: string;
    externalTransactionID: null | string;
    platform: string;
    processedAt: string;
    purchaseTokenHash: null | string;
    rawPayload: string;
    storeProductID: string;
    subscriptionID: string;
    transactionID: string;
    userID: string;
}

export type BillingStoreTransactionUpdate =
    Updateable<BillingStoreTransactionsTable>;

export type ChannelRow = Selectable<ChannelsTable>;

export interface ChannelsTable {
    channelID: string;
    name: string;
    serverID: string;
}

export type ChannelUpdate = Updateable<ChannelsTable>;

export type DevicePasskeyApprovalRow = Selectable<DevicePasskeyApprovalsTable>;

export interface DevicePasskeyApprovalsTable {
    approvedAt: string;
    approvedByDeviceID: null | string;
    approvedByPasskeyID: string;
    deviceID: string;
    userID: string;
}

export type DeviceRow = Selectable<DevicesTable>;

export interface DevicesTable {
    deleted: number;
    deviceID: string;
    lastLogin: string;
    name: string;
    owner: string;
    signKey: string;
}

export type DeviceUpdate = Updateable<DevicesTable>;

export type EmojiRow = Selectable<EmojisTable>;

export interface EmojisTable {
    emojiID: string;
    name: string;
    owner: string;
}

export type EmojiUpdate = Updateable<EmojisTable>;

export interface FederationNoncesTable {
    expiresAt: number;
    nonce: string;
    originHomeserverId: string;
}

export interface FederationRoomOutboxTable {
    attempts: number;
    createdAt: number;
    destinationHomeserverId: string;
    eventId: string;
    kind: string;
    nextAttemptAt: number;
    payload: string;
}

export interface FederationRoomTombstonesTable {
    deletedAt: number;
    homeserverId: string;
    permanent: number;
    revision: number;
    serverId: string;
}

export type FileRow = Selectable<FilesTable>;

export interface FilesTable {
    fileID: string;
    nonce: string;
    owner: string;
}

export type FileUpdate = Updateable<FilesTable>;

// ── Database schema ─────────────────────────────────────────────────────

export interface HomeserverMigrationsTable {
    accountId: string;
    authorization: string;
    completedAt: null | number;
    createdAt: number;
    destinationHomeserverId: string;
    deviceKey: string;
    mailCutoffAt: null | number;
    manifest: null | string;
    migrationId: string;
    nonce: string;
    sourceHomeserverId: string;
    transferExpiresAt: number;
}

// ── Row utility types ───────────────────────────────────────────────────

export type InviteRow = Selectable<InvitesTable>;
export interface InvitesTable {
    expiration: string;
    inviteID: string;
    owner: string;
    serverID: string;
}
export type InviteUpdate = Updateable<InvitesTable>;
export type MailRow = Selectable<MailTable>;

export interface MailTable {
    authorID: string;
    cipher: string;
    deliveryDeviceID: null | string;
    extra: null | string;
    forward: number;
    group: null | string;
    header: string;
    mailID: string;
    mailType: number;
    nonce: string;
    readerID: string;
    recipient: string;
    sender: string;
    time: string;
}
export type MailUpdate = Updateable<MailTable>;
export type NewAccountEntitlement = Insertable<AccountEntitlementsTable>;
export type NewBillingStoreSubscription =
    Insertable<BillingStoreSubscriptionsTable>;
export type NewBillingStoreTransaction =
    Insertable<BillingStoreTransactionsTable>;

export type NewChannel = Insertable<ChannelsTable>;
export type NewDevice = Insertable<DevicesTable>;
export type NewDevicePasskeyApproval = Insertable<DevicePasskeyApprovalsTable>;
export type NewEmoji = Insertable<EmojisTable>;
export type NewFile = Insertable<FilesTable>;

export type NewInvite = Insertable<InvitesTable>;
export type NewMail = Insertable<MailTable>;
export type NewNotificationSubscription =
    Insertable<NotificationSubscriptionsTable>;

export type NewOneTimeKey = Insertable<OneTimeKeysTable>;
export type NewPasskey = Insertable<PasskeysTable>;
export type NewPermission = Insertable<PermissionsTable>;
export type NewPreKey = Insertable<PreKeysTable>;

export type NewServer = Insertable<ServersTable>;
export type NewServiceMetric = Insertable<ServiceMetricsTable>;
export type NewUser = Insertable<UsersTable>;
export type NotificationSubscriptionRow =
    Selectable<NotificationSubscriptionsTable>;

export interface NotificationSubscriptionsTable {
    channel: string;
    createdAt: string;
    deviceID: string;
    enabled: number;
    events: string;
    platform: null | string;
    subscriptionID: string;
    token: string;
    updatedAt: string;
    userID: string;
}
export type NotificationSubscriptionUpdate =
    Updateable<NotificationSubscriptionsTable>;
export type OneTimeKeyRow = Selectable<OneTimeKeysTable>;

export interface OneTimeKeysTable {
    deviceID: string;
    index: number;
    keyID: string;
    publicKey: string;
    signature: string;
    userID: string;
}
export type OneTimeKeyUpdate = Updateable<OneTimeKeysTable>;
export type PasskeyRow = Selectable<PasskeysTable>;

export interface PasskeysTable {
    algorithm: number;
    createdAt: string;
    credentialID: string;
    lastUsedAt: null | string;
    name: string;
    passkeyID: string;
    publicKey: string;
    signCount: number;
    transports: string;
    userID: string;
}
export type PasskeyUpdate = Updateable<PasskeysTable>;
export type PermissionRow = Selectable<PermissionsTable>;

export interface PermissionsTable {
    permissionID: string;
    powerLevel: number;
    resourceID: string;
    resourceType: string;
    userID: string;
}
export type PermissionUpdate = Updateable<PermissionsTable>;
export type PreKeyRow = Selectable<PreKeysTable>;

export interface PreKeysTable {
    deviceID: string;
    index: number;
    keyID: string;
    publicKey: string;
    signature: string;
    userID: string;
}
export type PreKeyUpdate = Updateable<PreKeysTable>;

export interface RegistryAccountsTable {
    accountId: string;
    activeDeviceCount: number;
    deviceThreshold: number;
    epoch: string;
    homeserverId: string;
    nonce: string;
    recoveryCommitment: string;
    source: string;
}

export interface RegistryCursorsTable {
    checkpoint: string;
    sequence: string;
    source: string;
}

export interface RegistryDevicesTable {
    accountId: string;
    active: number;
    addedAtEpoch: string;
    deviceKey: string;
    revokedAtEpoch: null | string;
    source: string;
}

export interface RegistryHomeserversTable {
    active: number;
    endpoint: string;
    epoch: string;
    homeserverId: string;
    nonce: string;
    signingKey: string;
    source: string;
}

export interface RegistryUsernamesTable {
    accountId: string;
    nameHash: string;
    source: string;
    username: string;
}

export interface ServerDatabase {
    account_entitlements: AccountEntitlementsTable;
    billing_store_subscriptions: BillingStoreSubscriptionsTable;
    billing_store_transactions: BillingStoreTransactionsTable;
    channels: ChannelsTable;
    device_passkey_approvals: DevicePasskeyApprovalsTable;
    devices: DevicesTable;
    emojis: EmojisTable;
    federation_nonces: FederationNoncesTable;
    federation_room_outbox: FederationRoomOutboxTable;
    federation_room_tombstones: FederationRoomTombstonesTable;
    files: FilesTable;
    homeserver_migrations: HomeserverMigrationsTable;
    invites: InvitesTable;
    mail: MailTable;
    notification_subscriptions: NotificationSubscriptionsTable;
    oneTimeKeys: OneTimeKeysTable;
    passkeys: PasskeysTable;
    permissions: PermissionsTable;
    preKeys: PreKeysTable;
    registry_accounts: RegistryAccountsTable;
    registry_cursors: RegistryCursorsTable;
    registry_devices: RegistryDevicesTable;
    registry_homeservers: RegistryHomeserversTable;
    registry_usernames: RegistryUsernamesTable;
    servers: ServersTable;
    service_metrics: ServiceMetricsTable;
    users: UsersTable;
}

export type ServerRow = Selectable<ServersTable>;
export interface ServersTable {
    homeserverId: null | string;
    icon: null | string;
    name: string;
    revision: number;
    serverID: string;
}
export type ServerUpdate = Updateable<ServersTable>;

export type ServiceMetricRow = Selectable<ServiceMetricsTable>;
export interface ServiceMetricsTable {
    metric_key: string;
    metric_value: number;
}
export type ServiceMetricUpdate = Updateable<ServiceMetricsTable>;

export type UserRow = Selectable<UsersTable>;
export interface UsersTable {
    lastSeen: string;
    passwordHash: string;
    userID: string;
    username: string;
}
export type UserUpdate = Updateable<UsersTable>;
