/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

export { Client, DeviceApprovalRequiredError } from "./Client.js";
export type {
    Calls,
    Channel,
    Channels,
    ClientEvents,
    ClientOptions,
    Device,
    DeviceRegistrationResult,
    Devices,
    Emojis,
    Entitlements,
    FileProgress,
    FileRes,
    Files,
    Invites,
    Keys,
    Me,
    Message,
    Messages,
    MessageSendOptions,
    Migration,
    Moderation,
    NotificationSubscription,
    NotificationSubscriptionInput,
    Passkeys,
    PendingDeviceApprovalStatus,
    PendingDeviceRegistration,
    PendingDeviceRequest,
    Permission,
    Permissions,
    Server,
    ServerChannelBootstrap,
    Servers,
    Session,
    Sessions,
    User,
    Users,
    VexFile,
} from "./Client.js";
export { createCodec, msgpack } from "./codec.js";
export { HttpError, isHttpError } from "./http.js";
export type {
    HttpErrorOptions,
    HttpRequestRecord,
    HttpResponse,
} from "./http.js";
export {
    createMessageDeleteBatchEventExtra,
    createMessageDeleteEventExtra,
    createMessageEmbedExtra,
    createMessageUpdateEventExtra,
    MESSAGE_EXTRA_VERSION,
    parseMessageExtra,
    serializeMessageExtra,
} from "./messageExtra.js";
export type {
    EncryptedFileAttachmentReference,
    MessageDeleteEvent,
    MessageEmbed,
    MessageEmbedAction,
    MessageEmbedBlock,
    MessageEmbedCodeBlock,
    MessageEmbedDisplay,
    MessageEmbedDividerBlock,
    MessageEmbedField,
    MessageEmbedFileBlock,
    MessageEmbedGalleryBlock,
    MessageEmbedMarkdownBlock,
    MessageEmbedMediaBlock,
    MessageEmbedMediaItem,
    MessageEmbedMediaType,
    MessageEmbedSource,
    MessageEmbedTone,
    MessageEmoji,
    MessageExtra,
    MessageReaction,
    MessageReactionEvent,
    MessageUpdateEvent,
} from "./messageExtra.js";
export {
    clampLocalMessageRetentionDays,
    effectiveMessageRetentionHintDays,
    MAX_LOCAL_MESSAGE_RETENTION_DAYS,
} from "./retention.js";
export type { MessageUpdatePatch, Storage } from "./Storage.js";
export type {
    KeyPair,
    KeyStore,
    PreKeysCrypto,
    SessionCrypto,
    StoredCredentials,
    UnsavedPreKey,
} from "./types/index.js";
// Re-export app-facing types
export type {
    AccountEntitlements,
    AccountTier,
    AppleTransactionVerificationRequest,
    BillingAccountState,
    BillingProduct,
    BillingSubscription,
    BillingSubscriptionStatus,
    CallAction,
    CallEvent,
    CallParticipant,
    CallSession,
    CallSignalPayload,
    GooglePurchaseVerificationRequest,
    IceServerConfig,
    Invite,
    Passkey,
} from "@vex-chat/types";
