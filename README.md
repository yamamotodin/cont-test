# cont-test — node-forge@1.4.0 脆弱性検知テスト用ダミー

脆弱性検知器（SCA / SAST / コンテナスキャナなど）の検知動作を確認するための
**テスト用ダミープログラム**です。実運用・攻撃目的ではありません。

## 概要

- 既知の脆弱性を持つ [`node-forge` v1.4.0](https://github.com/digitalbazaar/forge/releases/tag/v1.4.0) に依存します。
- `v1.4.0` 以下に多数の既知アドバイザリ（High 深刻度を含む）が該当し、`v1.4.1` 以降で修正されています。
- `index.js` では、依存バージョンだけでなく、実際に脆弱な API（RSA 署名検証 / PEM デコード / ASN.1 デコード / AES-GCM / PKCS#7 パディング）を呼び出し、呼び出しベースの検知器にも反応しやすくしています。

## 該当アドバイザリ（抜粋）

| Advisory | 深刻度 | 内容 |
| --- | --- | --- |
| GHSA-6qrw-m8cv-hcxf | High | RSA PKCS#1 v1.5 署名偽造（非正規 DigestInfo） |
| GHSA-rhr8-3pm8-cq29 | High | ASN.1 `fromDer` のリソース枯渇 |
| GHSA-4487-j8r4-4g2f ほか | High | PEM デコードの ReDoS |
| GHSA-5cwg-6vw7-rj6p | Moderate | AES-GCM 認証バイパス（`tagLength` 未検証） |
| GHSA-2vgq-wchc-25w7 | Low | PKCS#7 パディング検証不備 |

> 一覧は `npm audit` で確認できます（`<=1.4.0` 該当多数）。

## 実行

```bash
npm install     # node-forge@1.4.0 を取得し package-lock.json を生成
npm start       # index.js を実行（ダミー処理）
npm audit       # 検知器の参考: 既知アドバイザリを表示
```

## 注意

- このリポジトリは **意図的に脆弱な依存を含みます**。CI の脆弱性ゲートで
  ブロックされることが期待される挙動です。
- 実運用環境へデプロイしないでください。
