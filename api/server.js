const express = require('express');
const { PrismaClient } = require('@prisma/client');

// パスワードハッシュ化
const bcrypt = require("bcrypt");

// JWTトークン生成
const jwt = require("jsonwebtoken");

// 環境変数=秘密の鍵が使えるようにdotenvを記述して使えるようにします🤗
require("dotenv");

//CORS対策
const cors = require("cors");

const app = express();
const prisma = new PrismaClient();

// jsで書いた文字列をjsonに変換するためのおまじないです
app.use(cors());
app.use(express.json());
const PORT = process.env.PORT || 3001;

// ユーザー登録API
app.post("/api/auth/register", async (req, res) => {
    const { username, email, password } = req.body;

    // 暗号化対応=bcryptを使ってハッシュ化する🤗
    const hashedPass = await bcrypt.hash(password, 10);

    // req.bodyの内容をログ出力して確認
    console.log("Request Body:", req.body);

    try {
        // Prisma Clientを使用してデータベースにユーザーを作成
        const user = await prisma.user.create({
            data: {
                username,
                email,
                password: hashedPass,
            },
        });

        // 作成されたユーザー情報をログ出力して確認
        console.log("Created User:", user);

        // 作成されたユーザー情報をJSON形式で返却
        return res.json({ user });
    } catch (error) {
        if (error.code === 'P2002') {
            if (error.meta.target.includes('email')) {
                return res.status(400).json({ error: "このメールアドレスは既に使用されています。" });
            } else if (error.meta.target.includes('id')) {
                return res.status(400).json({ error: "このIDは既に使用されています。" });
            }
        }
        console.error("Error creating user:", error);
        return res.status(500).json({ error: "ユーザー作成中にエラーが発生しました。" });
    }
});


// ログインAPI
app.post("/api/auth/login", async (req, res) => {
    // email, passwordをチェックするために取得します
    const { email, password } = req.body;

    // whereはSQL等で出てくる条件を絞るという条件です
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
        return res.status(401).json({
            error: "ユーザーは登録されていません",
        });
    }

    // compare bcryptのcompareは比較をしてチェックするおまじないです
    const isPasswordCheck = await bcrypt.compare(password, user.password);

    if (!isPasswordCheck) {
        return res.status(401).json({
            error: "パスワードが間違っています",
        });
    }

    // token = チケットのイメージです
    const token = jwt.sign({ id: user.id }, process.env.KEY, {
        expiresIn: "1d",
    });

    // トークンをレスポンスとして返却
    return res.json({token});
});

// ログアウトAPI
app.post("/api/auth/logout", (req, res) => {
    // クライアント側でセッションやトークンを削除するように指示
    res.setHeader('Set-Cookie', 'token=; HttpOnly; Max-Age=0'); // クッキーを無効化
    return res.json({ message: "ログアウトしました" });
});

// ログインしているユーザーのデータを取得するAPI
app.get("/api/auth/user", async (req, res) => {
    // リクエストヘッダーからトークンを取得
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: "トークンが提供されていません" });
    }

    try {
        // トークンを検証してユーザーIDを取得
        const decoded = jwt.verify(token, process.env.KEY);
        const userId = decoded.id;

        // ユーザーIDをログに出力
        console.log("Userid:", userId);

        const user = await prisma.user.findUnique({
            where: { id: userId },
        });

        if (!user) {
            return res.status(404).json({ error: "ユーザーが見つかりません" });
        }

        return res.json({ user });
    } catch (error) {
        console.error("Error fetching user data:", error);
        return res.status(500).json({ error: "ユーザーデータの取得中にエラーが発生しました" });
    }
});

// ログインしているユーザーのデータ編集するAPI
app.post("/api/auth/useredit", async (req, res) => {
    // リクエストヘッダーからトークンを取得
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: "トークンが提供されていません" });
    }

    try {
        // トークンを検証してユーザーIDを取得
        const decoded = jwt.verify(token, process.env.KEY);
        const userId = decoded.id;

        // ユーザーIDをログに出力
        console.log("Userid:", userId);

        const user = await prisma.user.findUnique({
            where: { id: userId },
        });

        if (!user) {
            return res.status(404).json({ error: "ユーザーが見つかりません" });
        }

        // ユーザー情報を更新
        const updatedUser = await prisma.user.update({
            where: { id: userId },
            data: {
                username: req.body.username || user.username,
                email: req.body.email || user.email,
                number: req.body.number || user.number,
                department: req.body.department || user.department,
                classification: req.body.classification || user.classification,
                hoby: req.body.hoby || user.hoby,
                business_experience: req.body.business_experience || user.business_experience,
            },
        });

        // 更新されたユーザー情報をJSON形式で返却
        return res.json({ user: updatedUser });
    } catch (error) {
        console.error("Error updating user data:", error);
        return res.status(500).json({ error: "ユーザーデータの更新中にエラーが発生しました" });
    }
});


// 全登録済みユーザーのデータを取得するAPI
app.get("/api/auth/users", async (req, res) => {
    try {
        const users = await prisma.user.findMany({
            select: {
                id: true,
                username: true,
                email: true,
                number: true,
                profile_image: true,
                department: true,
                classification: true,
                hoby: true,
                business_experience: true,
            },
        });

        return res.json({ users });
    } catch (error) {
        console.error("Error fetching users data:", error);
        return res.status(500).json({ error: "ユーザーデータの取得中にエラーが発生しました" });
    }
});

// 特定のIDのユーザーデータを取得するAPI
app.get("/api/auth/user/:id", async (req, res) => {
    // リクエストパラメータからユーザーIDを取得
    const userId = parseInt(req.params.id, 10);

    try {
        // Prisma Clientを使用してユーザーを検索
        const user = await prisma.user.findUnique({
            where: { id: userId },
        });

        if (!user) {
            return res.status(404).json({ error: "ユーザーが見つかりません" });
        }

        // ユーザー情報をJSON形式で返却
        return res.json({ user });
    } catch (error) {
        console.error("Error fetching user data:", error);
        return res.status(500).json({ error: "ユーザーデータの取得中にエラーが発生しました" });
    }
});

// appをエクスポート
module.exports = app;

// localでは、ここでサーバーを起動させます
// app.listen(PORT, () => console.log("server start"));