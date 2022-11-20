/**
 * Node.js snippet for validating a webhook request
 *
 * Inputs
 *  - signature: a string of hex pairs, found in headers['sortspoke-webhook-signature'] of the webhook event request
 *  - payload: the body (JSON) of the webhook event request
 *  - WEBHOOK_SECRET: this is found in SortSpoke on the details page for the webhook
 */

import { createHmac } from 'crypto';
import { TextEncoder } from 'util';

/**
 * Compares the received webhook signature against the hash of the request payload
 * @param signature
 * @param payload
 * @returns boolean
 */
export const payloadValidation = (signature, payload) => {
  // sanitize the received signature by removing dashes and making it lowercase
  const sigTransform = signature.split('-').join('').toLowerCase();

  const payloadHash = hashPayload(payload);

  return sigTransform === payloadHash;
};

/**
 * Hash the payload using the webhook secret as the seed
 * @param payload
 * @returns string
 */
export const hashPayload = (payload) => {
  const encoder = new TextEncoder();

  const secretBytes = encoder.encode(WEBHOOK_SECRET);

  const hmac = createHmac('SHA256', secretBytes);

  return hmac.update(payload).digest('hex');
};
