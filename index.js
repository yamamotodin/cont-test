/*
 * ============================================================================
 *  DUMMY / TEST PROGRAM — NOT FOR PRODUCTION
 * ============================================================================
 *
 *  目的:
 *    既知の脆弱性を持つ node-forge v1.4.0 への依存と、その脆弱な API 呼び出しを
 *    含むダミープログラムです。外部の脆弱性検知器 (SCA / SAST / コンテナスキャナ
 *    など) が正しく検知できるかを確認するためのテスト用サンプルであり、
 *    実運用やセキュリティ攻撃を目的としたものではありません。
 *
 *  対象バージョン:
 *    node-forge v1.4.0  (https://github.com/digitalbazaar/forge/releases/tag/v1.4.0)
 *    v1.4.0 以下に多数の既知アドバイザリが該当し、v1.4.1 以降で修正されています。
 *
 *  検知の観点:
 *    - 依存バージョンベースの検知 (package.json / package-lock.json の node-forge@1.4.0)
 *    - 呼び出しベースの検知 (以下で実際に脆弱な API を呼び出す)
 *
 *  このプログラムが触れる脆弱な API (抜粋):
 *    - forge.pem.decode               GHSA-4487... / PEM デコードの ReDoS
 *    - forge.asn1.fromDer             GHSA-rhr8-3pm8-cq29 / ASN.1 リソース枯渇
 *    - forge.pki RSA 署名検証          GHSA-6qrw-m8cv-hcxf / PKCS#1 v1.5 署名偽造
 *    - forge.cipher AES-GCM           GHSA-5cwg-6vw7-rj6p / tagLength 検証不備
 *    - forge.pkcs7 / CBC パディング    GHSA-2vgq-wchc-25w7 / PKCS#7 パディング検証不備
 * ============================================================================
 */

'use strict';

const forge = require('node-forge');

function banner(title) {
  console.log('\n=== ' + title + ' ===');
}

// --- 1. ライブラリ情報の表示 -------------------------------------------------
banner('node-forge version');
// node-forge はパッケージに埋め込まれたバージョン文字列を公開していないため、
// 依存の解決結果 (package.json) を参照する。
console.log('resolved node-forge version:', require('node-forge/package.json').version);

// --- 2. RSA 鍵生成と PKCS#1 v1.5 署名/検証 ----------------------------------
// GHSA-6qrw-m8cv-hcxf / GHSA-86w9-cpqp-85rv:
//   非正規な DigestInfo エンコーディングによる RSA PKCS#1 v1.5 署名偽造を受理。
banner('RSA PKCS#1 v1.5 sign / verify');
const keypair = forge.pki.rsa.generateKeyPair({ bits: 1024 });
const md = forge.md.sha256.create();
md.update('dummy message for scanner test', 'utf8');
const signature = keypair.privateKey.sign(md);
const verified = keypair.publicKey.verify(md.digest().bytes(), signature);
console.log('signature verified:', verified);

// --- 3. PEM デコード ---------------------------------------------------------
// GHSA-4487-j8r4-4g2f ほか: PEM デコード処理での正規表現 DoS (ReDoS)。
banner('PEM encode / decode');
const certPem = forge.pki.publicKeyToPem(keypair.publicKey);
const pemObjects = forge.pem.decode(certPem);
console.log('decoded PEM blocks:', pemObjects.length, '(type:', pemObjects[0].type + ')');

// --- 4. ASN.1 DER デコード ---------------------------------------------------
// GHSA-rhr8-3pm8-cq29: asn1.fromDer の BIT STRING デコードでリソース枯渇。
banner('ASN.1 fromDer');
const der = forge.pki.publicKeyToAsn1(keypair.publicKey);
const derBytes = forge.asn1.toDer(der).getBytes();
const asn1 = forge.asn1.fromDer(derBytes);
console.log('ASN.1 tag class/type:', asn1.tagClass, asn1.type);

// --- 5. AES-GCM 暗号化/復号 --------------------------------------------------
// GHSA-5cwg-6vw7-rj6p: tagLength オプションの未検証による AES-GCM 認証バイパス。
banner('AES-GCM encrypt / decrypt');
const key = forge.random.getBytesSync(16);
const iv = forge.random.getBytesSync(12);

const cipher = forge.cipher.createCipher('AES-GCM', key);
cipher.start({ iv: iv });
cipher.update(forge.util.createBuffer('secret payload', 'utf8'));
cipher.finish();
const encrypted = cipher.output.getBytes();
const tag = cipher.mode.tag.getBytes();

const decipher = forge.cipher.createDecipher('AES-GCM', key);
decipher.start({ iv: iv, tag: forge.util.createBuffer(tag) });
decipher.update(forge.util.createBuffer(encrypted));
const ok = decipher.finish();
console.log('AES-GCM decrypt ok:', ok, '/ plaintext:', decipher.output.toString());

// --- 6. AES-CBC + PKCS#7 パディング -----------------------------------------
// GHSA-2vgq-wchc-25w7: CBC/ECB 復号時の PKCS#7 パディング検証が不完全。
banner('AES-CBC (PKCS#7 padding)');
const cbcKey = forge.random.getBytesSync(16);
const cbcIv = forge.random.getBytesSync(16);

const cbcCipher = forge.cipher.createCipher('AES-CBC', cbcKey);
cbcCipher.start({ iv: cbcIv });
cbcCipher.update(forge.util.createBuffer('padded message', 'utf8'));
cbcCipher.finish();
const cbcEncrypted = cbcCipher.output.getBytes();

const cbcDecipher = forge.cipher.createDecipher('AES-CBC', cbcKey);
cbcDecipher.start({ iv: cbcIv });
cbcDecipher.update(forge.util.createBuffer(cbcEncrypted));
const cbcOk = cbcDecipher.finish();
console.log('AES-CBC decrypt ok:', cbcOk, '/ plaintext:', cbcDecipher.output.toString());

banner('done');
console.log('Dummy node-forge@1.4.0 usage completed. (test fixture for vulnerability scanners)');
