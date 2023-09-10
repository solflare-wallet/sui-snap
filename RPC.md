# RPC Methods

### getPublicKey

Returns the wallet's public key encoded as Base64.

#### Parameters

An object containing:

- `derivationPath` - Derivation paths segments that will be appended to m/44'/784'
- `confirm` - Whether to show a confirm dialog.

#### Returns

Base64 encoded public key.

Example:

```javascript
ethereum.request({
  method: 'wallet_invokeSnap',
  params: {
    snapId: 'npm:@elli-wallet/sui-snap',
    request: {
      method: 'getPublicKey',
      params: {
        derivationPath: [`0'`, `0'`],
        confirm: true
      }
   }
  }
});
```

### signTransaction

Sign a transaction and return the signature encoded as Base64.

#### Parameters

An object containing:

- `derivationPath` - Derivation paths segments that will be appended to m/44'/784'
- `message` - Transaction message encoded as Base64

#### Returns

An object containing:

- `publicKey` - Base64 encoded public key
- `signature` - Transaction signature encoded as Base64

Example:

```javascript
ethereum.request({
  method: 'wallet_invokeSnap',
  params: {
    snapId: 'npm:@elli-wallet/sui-snap',
    request: {
      method: 'signTransaction',
      params: {
        derivationPath: [`0'`, `0'`],
        message: '...'
      }
   }
  }
});
```

### signAllTransactions

Sign multiple transactions and return the signatures encoded as Base64.

#### Parameters

An object containing:

- `derivationPath` - Derivation paths segments that will be appended to m/44'/784'
- `messages` - An array of transaction messages encoded as Base64

#### Returns

An object containing:

- `publicKey` - Base64 encoded public key
- `signatures` - An array of transaction signatures encoded as Base64

Example:

```javascript
ethereum.request({
  method: 'wallet_invokeSnap',
  params: {
    snapId: 'npm:@elli-wallet/sui-snap',
    request: {
      method: 'signAllTransactions',
      params: {
        derivationPath: [`0'`, `0'`],
        messages: ['...', '...']
      }
   }
  }
});
```

### signMessage

Sign a message (can be either arbitrary bytes or a UTF-8 string) and return the signature encoded as Base64.

#### Parameters

An object containing:

- `derivationPath` - Derivation paths segments that will be appended to m/44'/784'
- `message` - Message encoded as Base64

#### Returns

An object containing:

- `publicKey` - Base64 encoded public key
- `signature` - Message signature encoded as Base64

Example:

```javascript
const bytes = new TextEncoder().encode('Lorem ipsum');
const base64Message = base64js.fromByteArray(bytes);

ethereum.request({
  method: 'wallet_invokeSnap',
  params: {
    snapId: 'npm:@elli-wallet/sui-snap',
    request: {
      method: 'signMessage',
      params: {
        derivationPath: [`0'`, `0'`],
        message: base64Message
      }
   }
  }
});
```
