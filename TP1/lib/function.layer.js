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

/**
 * Afficher un block.
 */
function showBlock(block) {
    $("#blocks").append(
        '<div class="row block">' +
        '<div class="col-12 mb-3">' +
        '<b>Block</b>' +
        '</div>' +
        '<div class="col-12">' +
        '<div class="form-group mb-2 row">' +
        '<label class="form-label form-label-sm col-4">' +
        'Hash du block' +
        '</label>' +
        '<div class="col-8">' +
        '<input type="text" class="form-control form-control-sm" value="' + block.getHash() + '" readonly>' +
        '</div>' +
        '</div>' +
        '<div class="form-group mb-2 row">' +
        '<label class="form-label form-label-sm col-4">' +
        'Hash du block précédent' +
        '</label>' +
        '<div class="col-8">' +
        '<input type="text" class="form-control form-control-sm" value="' + block.getPreviousBlockHash() + '" readonly>' +
        '</div>' +
        '</div>' +
        '<div class="form-group mb-2 row">' +
        '<label class="form-label form-label-sm col-4">' +
        'Hash des transactions' +
        '</label>' +
        '<div class="col-8">' +
        '<textarea class="form-control form-control-sm" rows="' +
        (block.getTransactionsHashs().length > 0 ? block.getTransactionsHashs().length : 1) +
        '" readonly>' +
        block.getTransactionsHashs().reduce(function(accumulatorTransactionsHashsHex, transactionHashHex) {
            return accumulatorTransactionsHashsHex + "\n" + transactionHashHex;
        }, "") +
        '</textarea>' +
        '</div>' +
        '</div>' +
        '<div class="form-group mb-2 row">' +
        '<label class="form-label form-label-sm col-4">' +
        'Hash du merkle root des transactions' +
        '</label>' +
        '<div class="col-8">' +
        '           <input type="text" class="form-control form-control-sm" value="' + block.getTransactionsMerkleRootHash() + '" readonly>' +
        '</div>' +
        '</div>' +
        '<div class="form-group mb-2 row">' +
        '<label class="form-label form-label-sm col-4">' +
        'Mineur' +
        '</label>' +
        '<div class="col-8">' +
        '<input type="text" class="form-control form-control-sm" value="' + block.getMiner() + '" readonly>' +
        '</div>' +
        '</div>' +
        '<div class="form-group mb-2 row">' +
        '<label class="form-label form-label-sm col-4">' +
        'Preuve de travail' +
        '</label>' +
        '<div class="col-8">' +
        '<input type="text" class="form-control form-control-sm" value="' + block.getProofOfWork() + '" readonly>' +
        '</div>' +
        '</div>' +
        '<div class="form-group row">' +
        '<label class="form-label form-label-sm col-4">' +
        'Date de création' +
        '</label>' +
        '<div class="col-8">' +
        '<input type="text" class="form-control form-control-sm" value="' + block.getCreationDate() + '" readonly>' +
        '</div>' +
        '</div>' +
        '</div>' +
        '</div>');
}