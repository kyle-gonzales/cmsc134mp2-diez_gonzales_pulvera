import OpenCrypto from "https://cdn.jsdelivr.net/npm/opencrypto@1.5.5/src/OpenCrypto.min.js";

// Initialize new OpenCrypto instance
const crypt = new OpenCrypto();

console.log(window.crypto.subtle.importKey());



const privateCryptoPromise = crypt.base64ToCrypto(privateKeyBase64, {
  name: "RSA-OAEP",
  hash: "SHA-256",
  usages: ["decrypt", "unwrapKey"],
});

// Use Promise.all() to handle conversion of both keys asynchronously
privateCryptoKey = Promise.all([privateCryptoPromise])
  .then(([privateCryptoKey]) => {
    console.log("Private Key (CryptoKey):", privateCryptoKey);
    // console.log("Public Key (CryptoKey):", publicCryptoKey);
    return privateCryptoKey;
  })
  .catch((error) => {
    console.error("Error:", error);
  });

let myPrint = () => {
  console.log("hello world");
};
export { myPrint };
