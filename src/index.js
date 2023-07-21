import nacl from 'tweetnacl';
import { blake2b } from '@noble/hashes/blake2b';
import base64js from 'base64-js';
import { panel, heading, text, copyable, divider } from '@metamask/snaps-ui';
import { deriveKeyPair } from './privateKey';
import { assertInput, assertConfirmation, bytesToHex } from './utils';

module.exports.onRpcRequest = async ({ origin, request }) => {
  // if (
  //   !origin ||
  //   (
  //     !origin.match(/^https?:\/\/localhost:[0-9]{1,4}$/) &&
  //     !origin.match(/^https?:\/\/(?:\S+\.)?elliwallet\.dev$/)
  //   )
  // ) {
  //   throw new Error('Invalid origin');
  // }

  const dappOrigin = request?.params?.origin || origin;
  const dappHost = (new URL(dappOrigin))?.host;

  switch (request.method) {
    case 'getPublicKey': {
      const { derivationPath, confirm = false } = request.params || {};

      assertInput(derivationPath);

      const keyPair = await deriveKeyPair(derivationPath);
      const pubkey = base64js.fromByteArray(keyPair.publicKey);

      if (confirm) {
        const accepted = await snap.request({
          method: 'snap_dialog',
          params: {
            type: 'confirmation',
            content: panel([
              heading('Confirm access'),
              text(dappHost),
              divider(),
              text(bytesToHex(keyPair.publicKey))
            ])
          }
        });

        assertConfirmation(accepted);
      }

      return pubkey;
    }
    case 'signTransaction': {
      const { derivationPath, message, simulationResult } = request.params || {};

      assertInput(derivationPath);
      assertInput(message);

      const simulationResultItems = Array.isArray(simulationResult) ? simulationResult.map((item) => text(item)) : [];

      const accepted = await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'confirmation',
          content: panel([
            heading('Sign transaction'),
            text(dappHost),
            divider(),
            ...simulationResultItems,
            copyable(message)
          ])
        }
      });

      assertConfirmation(accepted);

      const keyPair = await deriveKeyPair(derivationPath);
      const messageBytes = base64js.toByteArray(message);
      const hashedMessage = blake2b(messageBytes, { dkLen: 32 });
      const signature = nacl.sign.detached(hashedMessage, keyPair.secretKey);
      return {
        publicKey: base64js.fromByteArray(keyPair.publicKey),
        signature: base64js.fromByteArray(signature)
      };
    }
    case 'signAllTransactions': {
      const { derivationPath, messages, simulationResults } = request.params || {};

      assertInput(derivationPath);
      assertInput(messages);
      assertInput(messages.length);

      const keyPair = await deriveKeyPair(derivationPath);

      const uiElements = [];

      for (let i = 0; i < messages?.length; i++) {
        uiElements.push(divider());
        uiElements.push(text(`Transaction ${i + 1}`));
        if (Array.isArray(simulationResults?.[i])) {
          simulationResults[i].forEach((item) => uiElements.push(text(item)));
        }
        uiElements.push(copyable(messages?.[i]));
      }

      const accepted = await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'confirmation',
          content: panel([
            heading('Sign transactions'),
            text(dappHost),
            ...uiElements
          ])
        }
      });

      assertConfirmation(accepted);

      const signatures = messages
        .map((message) => base64js.toByteArray(message))
        .map((message) => blake2b(message, { dkLen: 32 }))
        .map((message) => nacl.sign.detached(message, keyPair.secretKey))
        .map((signature) => base64js.fromByteArray(signature));

      return {
        publicKey: base64js.fromByteArray(keyPair.publicKey),
        signatures
      };
    }
    case 'signMessage': {
      const { derivationPath, message } = request.params || {};

      assertInput(derivationPath);
      assertInput(message);

      const keyPair = await deriveKeyPair(derivationPath);

      const messageBytes = base64js.toByteArray(message);

      let decodedMessage = '';
      try {
        decodedMessage = (new TextDecoder()).decode(messageBytes);
      } catch (error) {
        decodedMessage = 'Unable to decode message';
      }

      const accepted = await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'confirmation',
          content: panel([
            heading('Sign message'),
            text(dappHost),
            divider(),
            copyable(decodedMessage)
          ])
        }
      });

      assertConfirmation(accepted);

      const hashedMessage = blake2b(messageBytes, { dkLen: 32 });
      const signature = nacl.sign.detached(hashedMessage, keyPair.secretKey);

      return {
        publicKey: base64js.fromByteArray(keyPair.publicKey),
        signature: base64js.fromByteArray(signature)
      };
    }
    default:
      throw {
        code: 4200,
        message: 'The requested method is not supported.'
      };
  }
};
