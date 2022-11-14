if (crypto.subtle && ("encrypt" in crypto.subtle)) {
  console.log("Supporting WebCrypto");
} else {
  console.log("Not supporting WebCrypto");
}
