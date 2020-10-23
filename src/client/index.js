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

(async () => {
  try {
    const clientKeyPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveKey']
    );
    const exportedClientPublicKey = await crypto.subtle.exportKey(
      'raw',
      clientKeyPair.publicKey
    );
    const exportedServerPublicKey = await fetch('/exchange-keys', {
      method: 'POST',
      body: exportedClientPublicKey,
    }).then((r) => r.arrayBuffer());
    const importedServerPublicKey = await crypto.subtle.importKey(
      'raw',
      exportedServerPublicKey,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );
    const derivedClientSecretKey = await crypto.subtle.deriveKey(
      { name: 'ECDH', public: importedServerPublicKey },
      clientKeyPair.privateKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['decrypt', 'encrypt']
    );
    const exportedClientSecretKey = await crypto.subtle.exportKey(
      'raw',
      derivedClientSecretKey
    );
    console.log('secret:', formatArrayBuffer(exportedClientSecretKey));
    const importedClientSecretKey = await crypto.subtle.importKey(
      'raw',
      exportedClientSecretKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt', 'encrypt']
    );
    const clientMessage = 'test message from client';
    const encodedClientMessage = new TextEncoder().encode(clientMessage).buffer;
    const iv = crypto.getRandomValues(new Uint8Array(12)).buffer;
    const encryptedClientMessage = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      importedClientSecretKey,
      encodedClientMessage
    );
    const encryptedClientBody = concatArrayBuffers(iv, encryptedClientMessage);
    const encryptedServerBody = await fetch('/exchange-data', {
      method: 'POST',
      body: encryptedClientBody,
    }).then((r) => r.arrayBuffer());
    const decryptedServerMessage = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: encryptedServerBody.slice(0, 12) },
      importedClientSecretKey,
      encryptedServerBody.slice(12)
    );
    const decodedServerMessage = new TextDecoder().decode(
      decryptedServerMessage
    );
    console.log('message:', decodedServerMessage);
  } catch (error) {
    console.error(error);
  }
})();
