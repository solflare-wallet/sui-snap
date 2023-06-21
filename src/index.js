import nacl from 'tweetnacl';
import { blake2b } from '@noble/hashes/blake2b';
import base64js from 'base64-js';
import { panel, heading, text, copyable, divider } from '@metamask/snaps-ui';
import { deriveKeyPair } from './privateKey';
import { assertInput, assertConfirmation } from './utils';

module.exports.onRpcRequest = async ({ origin, request }) => {
  switch (request.method) {
    case 'getPublicKey': {
      const [ path, confirm = false ] = request.params || [];

      assertInput(path);

      if (confirm) {
        const accepted = await snap.request({
          method: 'snap_dialog',
          params: {
            type: 'confirmation',
            content: panel([
              heading('Confirm access'),
              text(`${origin} wants to know your Sui address`)
            ])
          }
        });

        assertConfirmation(accepted);
      }

      const keyPair = await deriveKeyPair(path);
      return base64js.fromByteArray(keyPair.publicKey);
    }
    case 'signTransaction': {
      const [ path, message ] = request.params || [];

      assertInput(path);
      assertInput(message);

      const accepted = await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'confirmation',
          content: panel([
            heading('Sign transaction'),
            text(`${origin} is requesting to sign the following transaction`),
            copyable(message)
          ])
        }
      });

      assertConfirmation(accepted);

      const keyPair = await deriveKeyPair(path);
      const messageBytes = base64js.toByteArray(message);
      const hashedMessage = blake2b(messageBytes, { dkLen: 32 });
      const signature = nacl.sign.detached(hashedMessage, keyPair.secretKey);
      return {
        publicKey: base64js.fromByteArray(keyPair.publicKey),
        signature: base64js.fromByteArray(signature)
      };
    }
    case 'signAllTransactions': {
      const [ path, messages ] = request.params || [];

      assertInput(path);
      assertInput(messages);
      assertInput(messages.length);

      const keyPair = await deriveKeyPair(path);

      const uiElements = [];

      for (let i = 0; i < messages?.length; i++) {
        uiElements.push(divider());
        uiElements.push(text(`Transaction ${i + 1}`));
        uiElements.push(copyable(messages?.[i]));
      }

      const accepted = await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'confirmation',
          content: panel([
            heading('Sign transactions'),
            text(`${origin} is requesting to sign the following transactions`),
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
      const [ path, message ] = request.params || [];

      assertInput(path);
      assertInput(message);

      const keyPair = await deriveKeyPair(path);

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
            text(`${origin} is requesting to sign the following message`),
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
