/**
 * sha256.
 */
function sha256(content) {
    return CryptoJS.SHA256(content).toString();
}

/**
 * Passer de décimal à hexadécimal.
 */
function decimalToHex(number) {
    return number.toString(16);
}

/**
 * Passer de String à Uint8Array.
 */
function hexStringToHexUint8Array(hexString) {
    return new Uint8Array(hexString.match(/.{1,2}/g).map(hex => parseInt(hex, 16)));
}

/**
 * Passer de Uint8Array à String.
 */
function hexUint8ArrayToHexString(hexUint8Array) {
    return hexUint8Array.reduce((hexString, hex) => hexString + hex.toString(16).padStart(2, '0'), '');
}

/**
 * Fonction pour générer des clés privée et publique.
 *
 * Les clés retournées sont en hexadécimales.
 */
function generateKeys() {
    let keyPair = nacl.sign.keyPair();
    keyPair.privateKey = hexUint8ArrayToHexString(keyPair.secretKey);
    keyPair.publicKey = hexUint8ArrayToHexString(keyPair.publicKey);
    return keyPair;
}

/**
 * Chiffrer un contenu avec une clé privée.
 *
 * Le message chiffré retourné est en hexadécimal.
 */
function encrypt(content, privateKey) {
    return hexUint8ArrayToHexString(nacl.sign(nacl.util.decodeUTF8(content),
        hexStringToHexUint8Array(privateKey)));
}

/**
 * Déchiffrer un contenu chiffré, avec une clé publique.
 *
 * Si mauvaise clé publique, null renvoyé.
 */
function decrypt(encryptedContent, publicKey) {
    let message = nacl.sign.open(hexStringToHexUint8Array(encryptedContent),
        hexStringToHexUint8Array(publicKey));
    return message ? nacl.util.encodeUTF8(message) : null;
}

let sequenceValues = 1;
/**
 * Afficher une valeur avec un intitulé.
 */
function showValue(label, value) {
    $('#values').append(
        '<div class="form-group col-12 mb-3">' +
        '<label for="value" class="form-label form-label-sm">' +
        label +
        '</label>' +
        '<textarea id="value-' + sequenceValues + '" class="form-control form-control-sm" readonly>' + value + '</textarea>' +
        '</div>');
    sequenceValues++;
}