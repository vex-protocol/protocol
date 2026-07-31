/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

export const ALLOWED_IMAGE_TYPES: readonly string[] = [
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/apng",
    "image/avif",
    "image/webp",
];

export function isAllowedImageType(value: string): boolean {
    return ALLOWED_IMAGE_TYPES.some((type) => type === value);
}
