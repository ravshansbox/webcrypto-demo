const express = require('express');
const { Crypto } = require('node-webcrypto-ossl');

function concatArrayBuffers(...buffers) {
  const length = buffers.reduce((agg, buffer) => agg + buffer.byteLength, 0);
  return buffers.reduce(
    (agg, buffer) => {
      agg.result.set(new Uint8Array(buffer), agg.position);
      agg.position = +buffer.byteLength;
      return agg;
    },
    { position: 0, result: new Uint8Array(length) }
  ).result.buffer;
}

function formatArrayBuffer(arrayBuffer) {
  return [...new Uint8Array(arrayBuffer)]
    .map((el) => el.toString(16).padStart(2, '0'))
    .join('');
}

const HTTP_PORT = 3000;
const crypto = new Crypto();
const app = express();

app.use(express.static('src/client'));

app.use((request, response, next) => {
  const chunks = [];
  request.on('data', (chunk) => {
    chunks.push(chunk);
  });
  request.on('end', () => {
    request.body = Buffer.concat(chunks);
    next();
  });
  request.on('error', (error) => {
    response.send({ message: error.message });
  });
});

const sessionSecretKeys = {};
app.post('/exchange-keys', async (request, response, next) => {
  const { session } = request.query;
  const exportedClientPublicKey = request.body;
  try {
    const importedClientPublicKey = await crypto.subtle.importKey(
      'raw',
      exportedClientPublicKey,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );
    const serverKeyPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveKey']
    );
    const derivedServerSecretKey = await crypto.subtle.deriveKey(
      { name: 'ECDH', public: importedClientPublicKey },
      serverKeyPair.privateKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['decrypt', 'encrypt']
    );
    const exportedServerSecretKey = await crypto.subtle.exportKey(
      'raw',
      derivedServerSecretKey
    );
    console.log('secret:', formatArrayBuffer(exportedServerSecretKey));
    const exportedServerPublicKey = await crypto.subtle.exportKey(
      'raw',
      serverKeyPair.publicKey
    );
    response.send(Buffer.from(exportedServerPublicKey));
    sessionSecretKeys[session] = exportedServerSecretKey;
  } catch (error) {
    next(error);
  }
});

app.post('/exchange-data', async (request, response, next) => {
  const { session } = request.query;
  const encryptedClientBody = request.body;
  try {
    const exportedServerSecretKey = sessionSecretKeys[session];
    const importedServerSecretKey = await crypto.subtle.importKey(
      'raw',
      exportedServerSecretKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt', 'encrypt']
    );
    const decryptedClientMessage = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: encryptedClientBody.slice(0, 12) },
      importedServerSecretKey,
      encryptedClientBody.slice(12)
    );
    const decodedClientMessage = new TextDecoder().decode(
      decryptedClientMessage
    );
    console.log('message:', decodedClientMessage);
    const serverMessage = 'test message from server';
    const encodedServerMessage = new TextEncoder().encode(serverMessage).buffer;
    const iv = crypto.getRandomValues(new Uint8Array(12)).buffer;
    const encryptedServerMessage = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      importedServerSecretKey,
      encodedServerMessage
    );
    const encryptedServerBody = concatArrayBuffers(iv, encryptedServerMessage);
    response.send(Buffer.from(encryptedServerBody));
  } catch (error) {
    next(error);
  }
});

app.listen(HTTP_PORT, () => {
  console.info(`Listening on port ${HTTP_PORT}`);
});
