import nacl from 'tweetnacl';
import { blake2b } from '@noble/hashes/blake2b';
import base64js from 'base64-js';
import { deriveKeyPair } from './privateKey';
import { assertInput, assertConfirmation, assertAllStrings, assertIsString, assertIsBoolean, assertIsArray, bytesToHex } from './utils';
import { renderGetPublicKey, renderSignTransaction, renderSignAllTransactions, renderSignMessage } from './ui';

module.exports.onRpcRequest = async ({ origin, request }) => {
  if (
    !origin ||
    (
      !origin.match(/^https?:\/\/localhost:[0-9]{1,4}$/) &&
      !origin.match(/^https?:\/\/(?:\S+\.)?elliwallet\.dev$/)
    )
  ) {
    throw new Error('Invalid origin');
  }

  const dappOrigin = request?.params?.origin || origin;
  const dappHost = (new URL(dappOrigin))?.host;

  switch (request.method) {
    case 'getPublicKey': {
      const { derivationPath, confirm = false } = request.params || {};

      assertInput(derivationPath);
      assertIsString(derivationPath);
      assertIsBoolean(confirm);

      const keyPair = await deriveKeyPair(derivationPath);
      const pubkey = base64js.fromByteArray(keyPair.publicKey);

      if (confirm) {
        const accepted = await renderGetPublicKey(dappHost, bytesToHex(keyPair.publicKey));
        assertConfirmation(accepted);
      }

      return pubkey;
    }
    case 'signTransaction': {
      const { derivationPath, message, simulationResult = [], displayMessage = true } = request.params || {};

      assertInput(derivationPath);
      assertIsString(derivationPath);
      assertInput(message);
      assertIsString(message);
      assertIsArray(simulationResult);
      assertAllStrings(simulationResult);
      assertIsBoolean(displayMessage);

      const accepted = await renderSignTransaction(dappHost, message, simulationResult, displayMessage);
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
      const { derivationPath, messages, simulationResults = [], displayMessage = true } = request.params || {};

      assertInput(derivationPath);
      assertIsString(derivationPath);
      assertInput(messages);
      assertIsArray(messages);
      assertInput(messages.length);
      assertAllStrings(messages);
      assertIsArray(simulationResults);
      assertInput(messages.length === simulationResults.length);
      assertIsBoolean(displayMessage);

      const accepted = await renderSignAllTransactions(dappHost, messages, simulationResults, displayMessage);
      assertConfirmation(accepted);

      const keyPair = await deriveKeyPair(derivationPath);
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
      assertIsString(derivationPath);
      assertInput(message);
      assertIsString(message);

      const keyPair = await deriveKeyPair(derivationPath);

      const messageBytes = base64js.toByteArray(message);

      let decodedMessage = '';
      try {
        decodedMessage = (new TextDecoder()).decode(messageBytes);
      } catch (error) {
        decodedMessage = 'Unable to decode message';
      }

      const accepted = await renderSignMessage(dappHost, decodedMessage);
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
