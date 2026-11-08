# Passkey / Windows Hello ログイン (Node.js + PostgreSQL)

## 動作要件
- Node.js 20 以上
- PostgreSQL
- Windows 10/11 で Windows Hello（顔・指紋・PIN のいずれか）を設定済み
  （設定 → アカウント → サインイン オプション）
- Edge / Chrome / Firefox の最新版

## セットアップ
```bash
createdb passkey_app            # または pgAdmin で空のDBを作成
npm install
copy .env.example .env          # macOS/Linux は cp。中身（DB接続・SESSION_SECRET）を編集
npm start
```
`http://localhost:3000` をブラウザで開きます。テーブルは起動時に自動作成されます (`schema.sql`)。

## 使い方
1. ユーザー名を入力 → 「Passkey を作成して登録」→ Windows Hello のダイアログで認証
2. ログアウト後、「Windows Hello でログイン」→ ユーザー名入力なしでログイン可能

## Windows Hello 利用のポイント
- `PLATFORM_ONLY=true` で Windows Hello など端末内蔵の認証器に限定（`false` でスマホ/セキュリティキーも可）
- `userVerification: 'required'` により PIN/生体認証を必須にしています
- `localhost` は HTTP でも動作しますが、**本番は HTTPS 必須**です

## 本番運用時の設定
- `RP_ID` = ドメイン名（例: `example.com`）、`ORIGIN` = `https://example.com`
- `NODE_ENV=production`（Cookie に secure が付きます。リバースプロキシ配下なら trust proxy 設定済み）
- `RP_ID` を後から変えると既存の Passkey は使えなくなります
- 推奨追加対策: レート制限 (express-rate-limit)、helmet、アカウント復旧手段（複数 Passkey の登録を促す等）

## ファイル構成
- `server.js` … Express API（登録 / 認証 / セッション）
- `schema.sql` … users / credentials テーブル
- `public/` … フロントエンド（外部ライブラリ不要。WebAuthn API を直接使用）
