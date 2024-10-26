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

// supabaseのstorageへのアップロード機能を使うためのおまじないです！
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');

const prisma = new PrismaClient();

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

const app = express();
// jsで書いた文字列をjsonに変換するためのおまじないです
app.use(cors());
app.use(express.json());

// multer は、Node.js のミドルウェアで、ファイルのアップロードを処理する
// memoryStorageで、アップロードされたファイルをメモリ内に一時保存します。
const upload = multer({ storage: multer.memoryStorage() });

const PORT = process.env.PORT || 3001;

// リクエスト毎にトークンの検証確認 authorization

// authorization ヘッダーが存在する場合、値をスペースで分割し、2番目の部分（トークン）を取得します。
// authHeader.split(' ')[1] は、Bearer の後に続くトークン部分を抽出します。
const AuthenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    // jwt.verify を使用して、トークンを検証。
    jwt.verify(token, process.env.KEY, (err, user) => {
        if (err) {
            console.error('JWT verification error:', err);
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
};

// Supabase クライアントの設定
const getSupabaseClient = (token) => {
    return createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
        headers: {
            authorization: `Bearer ${token}`
        }
    });
};

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
app.get("/api/auth/user",async (req, res) => {
    // リクエストヘッダーからトークンを取得
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: "トークンが提供されていません" });
    }

    try {
        // トークンを検証してdecodeに変数としてトークンを格納
        const decoded = jwt.verify(token, process.env.KEY);
        // トークンからユーザーIDを取得
        const userId = decoded.id;

        // ユーザーIDをログに出力
        // console.log("Userid:", userId);
        
        // Prisma Clientを使用してdbのidとトークンから取得したユーザーid(リクエストあったユーザー)を
        // 検索してデータ取得
        const user = await prisma.user.findUnique({
            where: { id: userId },
        });
        // console.log("getdata:", user);
        
        if (!user) {
            return res.status(404).json({ error: "ユーザーが見つかりません" });
        }

        // ユーザー情報をJSON形式でuserに格納してフロントへ送信
        return res.json({ user });
    } catch (error) {
        console.error("Error fetching user data:", error);
        return res.status(500).json({ error: "ユーザーデータの取得中にエラーが発生しました" });
    }
});

// ログインユーザー情報edit API

// Multerを使用してprofile_imageをreq.fileに格納。
app.post('/api/auth/useredit', AuthenticateToken, upload.single('profile_image'), async (req, res) => {
    try {
        // リクエストボディからユーザー情報を取得
        const { id, number, department, classification, hoby, business_experience} = req.body;
        // 画像のURL格納するprofileImageUrlをnullで初期化
        let profileImageUrl = null;
        
        const supabase = getSupabaseClient(req.headers['authorization'].split(' ')[1]); 

        // 画像がアップロードされた場合
        if (req.file) {
            // フロントエンドから送信されたファイル名:fileNameを使用
            const fileName = req.file.originalname;
            // supabaseのstorage imagesにファイルをアップロード
            const { data, error } = await supabase
                .storage
                .from('User_image')
                .upload(fileName, req.file.buffer, {
                    contentType: req.file.mimetype,
                    upsert: true
                });

            if (error) throw error;

            // ファイル名をURLエンコード
            const encodedFileName = encodeURIComponent(fileName);

            // supabaseのstorage内における画像のURLを取得 ;
            // urlDataは画像URLを格納場所
            // publicUrlは画像URL
            // getPublicUrl=encodedFileNameで指定された画像URLをimagesから取得
            const { data: urlData } = supabase
                .storage
                .from('User_image')
                .getPublicUrl(encodedFileName);

            // console.log("URL Data:", urlData);
            // urlDataに入った画像URL＝publicUrlをprofileImageUrlに格納
            profileImageUrl = urlData.publicUrl;
        }
        // console.log("Profile Image URL:", profileImageUrl);
        // ユーザー情報の更新
        const { data: updatedUser, error: updateError } = await supabase
            .from('User')
            .update({
                number,
                department,
                classification,
                hoby,
                business_experience,
                profile_image: profileImageUrl
            })
            .eq('id', id);

        if (updateError) throw updateError;

        return res.json({ user: updatedUser });

    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ error: 'ユーザー情報の更新中にエラーが発生しました' });
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

        orderBy: {
            number: 'asc', // numberフィールドで昇順にソート
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

// ・・・・・・・これ以降がdocument tableのAPIです・・・・・


// 新規作成のdocmentデータをdbへ送信するAPI
app.post("/api/auth/doc", AuthenticateToken, async (req, res) => {

    // リクエストヘッダーからトークンを取得
    const supabase = getSupabaseClient(req.headers['authorization'].split(' ')[1]); 


    try {
        // // トークンからユーザーIDを取得
        const tokenId = req.user.id;

        // ユーザーIDをログに出力
        console.log("tokenId:", tokenId);

        // リクエストボディからデータを取得
        const { title, theme, overview, results, objects } = req.body;

        // 取得したデータをログに出力して確認
        console.log("Request Body Data:", { title, theme, overview, results, objects });

        // objectsをJSON文字列に変換
        const objectsString = JSON.stringify(objects);

        /// Prisma Clientを使用してデータを新規作成
        const document = await prisma.document.create({
            data: {
                title,
                theme,
                overview,
                results,
                objects: objectsString,
                userId: tokenId
            }
        });
            // .eq('id', tokenId);

        console.log("senddata:", document);
    
        // 作成されたドキュメントをJSON形式で返却
        return res.json({ document });
    } catch (error) {
        console.error("Error creating document:", error);
        return res.status(500).json({ error: "documentデータの作成中にエラーが発生しました" });
    }
});

// ログインしているユーザーのdocumetデータを取得するAPI
app.get("/api/auth/documents", async (req, res) => {
    // リクエストヘッダーからトークンを取得
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: "トークンが提供されていません" });
    }

    try {
        // トークンを検証してdecodeに変数としてトークンを格納
        const decoded = jwt.verify(token, process.env.KEY);
        // トークンからユーザーIDを取得
        const userId = decoded.id;

        // ユーザーIDをログに出力
        console.log("Userid:", userId);

        // Prisma Clientを使用してdbのidとトークンから取得したユーザーid(リクエストあったユーザー)を
        // 検索してデータ取得
        const docdata = await prisma.document.findMany({
            where: { userId: userId },
        });
        console.log("getdocdata:", docdata);

        if (!docdata || docdata.length === 0) {
            return res.status(404).json({ error: "documentデータが見つかりません" });
        }

        // 取得したデータをJSON形式で返却
        return res.json({ documents: docdata });
    } catch (error) {
        console.error("Error fetching document data:", error);
        return res.status(500).json({ error: "documentデータの取得中にエラーが発生しました" });
    }
});


// Mypageの編集ボタンで選択したdocumetデータを取得するAPI
app.get("/api/auth/document/:id", async (req, res) => {
    console.log("Received request for document ID:", req.params.id);
    // リクエストパラメータからユーザーIDを取得
    const documentId = parseInt(req.params.id, 10);

    if (isNaN(documentId)) {
        return res.status(400).json({ error: "無効なドキュメントIDです" });
    }

    try {
        // Prisma Clientを使用してユーザーを検索
        const document = await prisma.document.findUnique({
            where: { id: documentId },
        });
        console.log("geteditdocdata:", document);

        if (!document) {
            return res.status(404).json({ error: "ドキュメントが見つかりません" });
        }

        // ユーザー情報をJSON形式で返却
        return res.json({document });
    } catch (error) {
        console.error("Error fetching document data:", error);
        return res.status(500).json({ error: "ドキュメントデータの取得中にエラーが発生しました" });
    }
});

// ドキュメントデータを上書きするAPI
app.post("/api/auth/docupdata", AuthenticateToken, async (req, res) => {

    // リクエストヘッダーからトークンを取得
    const supabase = getSupabaseClient(req.headers['authorization'].split(' ')[1]);


    try {
        // // トークンからユーザーIDを取得
        const tokenId = req.user.id;

        // ユーザーIDをログに出力
        console.log("tokenId:", tokenId);

        // リクエストボディからデータを取得
        const { documentId, title, theme, overview, results, objects } = req.body;

        // 取得したデータをログに出力して確認
        console.log("Request Body Data:", { documentId,title, theme, overview, results, objects });

        // documentId が正しく取得できているか確認
        if (!documentId) {
            return res.status(400).json({ error: "documentId が指定されていません" });
        }

        // documentId を整数に変換
        const documentIdInt = parseInt(documentId, 10);
        if (isNaN(documentIdInt)) {
            return res.status(400).json({ error: "documentId が無効です" });
        }


        // objectsをJSON文字列に変換
        const objectsString = JSON.stringify(objects);

        /// Prisma Clientを使用してデータを上書き
        const updatadDocument = await prisma.document.update({
            where: { id: documentIdInt },
            data: {
                title,
                theme,
                overview,
                results,
                objects: objectsString,
            },
        });
       
        console.log("senddata:", updatadDocument);

        // 作成されたドキュメントをJSON形式で返却
        return res.json({ updatadDocument });
    } catch (error) {
        console.error("Error updata document:", error);
        return res.status(500).json({ error: "documentデータの作成中にエラーが発生しました" });
    }
});

// 特定のIDのユーザードキュメントデータを取得するAPI
app.get("/api/auth/menberdocument/:id", async (req, res) => {
    // リクエストパラメータからユーザーIDを取得
    const documentId = parseInt(req.params.id, 10);

    try {
        // Prisma Clientを使用してdbのidとトークンから取得したユーザーid(リクエストあったユーザー)を
        // 検索してデータ取得
        const docdata = await prisma.document.findMany({
            where: { userId: documentId },
        });
        console.log("getdocdata:", docdata);

        if (!docdata || docdata.length === 0) {
            return res.status(404).json({ error: "documentデータが見つかりません" });
        }

        // 取得したデータをJSON形式で返却
        return res.json({ documents: docdata });
    } catch (error) {

        console.error("Error fetching document data:", error);
        return res.status(500).json({ error: "documentデータの取得中にエラーが発生しました" });
    }
});

//////////以下がdocument用のイラスト処理用のAPIです//////////

// イラストdb登録 API

// Multerを使用してprofile_imageをreq.fileに格納。
app.post('/api/auth/imagecreat', AuthenticateToken, upload.single('file'), async (req, res) => {
    try {
        // リクエストボディからユーザー情報を取得
        const { id, kinds, imageName } = req.body;
        // 画像のURL格納するdocImageUrlをnullで初期化
        let docImageUrl = null;

        const supabase = getSupabaseClient(req.headers['authorization'].split(' ')[1]);

        // 画像がアップロードされた場合
        if (req.file) {
            // フロントエンドから送信されたファイル名:romajiImageNameを使用
            const fileName = req.file.originalname;
            // supabaseのstorage imagesにファイルをアップロード
            const { data, error } = await supabase
                .storage
                .from('Doc_illustration')
                .upload(fileName, req.file.buffer, {
                    contentType: req.file.mimetype,
                    upsert: true
                });

            if (error) throw error;

            // ファイル名をURLエンコード
            const encodedFileName = encodeURIComponent(fileName);

            // supabaseのstorage内における画像のURLを取得 ;
            // urlDataは画像URLを格納場所
            // publicUrlは画像URL
            // getPublicUrl=encodedFileNameで指定された画像URLをimagesから取得
            const { data: urlData } = supabase
                .storage
                .from('Doc_illustration')
                .getPublicUrl(encodedFileName);

            // console.log("URL Data:", urlData);
            // urlDataに入った画像URL＝publicUrlをdocImageUrlに格納
            docImageUrl = urlData.publicUrl;
        }

        // console.log("Profile Image URL:", docImageUrl);
        // 取得したデータをデータベースに保存
        const { data: newImage, error: insertError } = await supabase
            .from('Imagelist')
            .insert({
                kinds,
                imageName,
                imageUrl: docImageUrl,
            });

        if (insertError) throw insertError;

        return res.json({ image: newImage });

    } catch (error) {
        console.error('Error creating image:', error);
        res.status(500).json({ error: '画像の作成中にエラーが発生しました' });
    }
});

// 
app.get('/api/auth/docimage', AuthenticateToken, async (req, res) => {
    try {
        // クエリパラメータからkindsを取得
        const { kinds } = req.query;

        const supabase = getSupabaseClient(req.headers['authorization'].split(' ')[1]);

        // Supabaseのテーブルからkindsに一致するデータを取得
        const { data, error } = await supabase
            .from('Imagelist')
            .select('imageUrl')
            .eq('kinds', kinds)
            .order('id', { ascending: true });

        if (error) throw error;

        // 取得したデータをクライアントに返す
        return res.json(data);

    } catch (error) {
        console.error('Error fetching images:', error);
        res.status(500).json({ error: '画像の取得中にエラーが発生しました' });
    }
});

// クライアント側で選択されたジャンルのUrlをdbから取得するAPI
app.get('/api/auth/docimage', AuthenticateToken, async (req, res) => {
    try {
        // クエリパラメータからkindsを取得
        const { kinds } = req.query;

        const supabase = getSupabaseClient(req.headers['authorization'].split(' ')[1]);

        // Supabaseのテーブルからkindsに一致するデータを取得
        const { data, error } = await supabase
            .from('Imagelist')
            .select('imageUrl','imageName')
            .eq('kinds', kinds)
            .order('id', { ascending: true });

        if (error) throw error;

        // 取得したデータをクライアントに返す
        return res.json(data);

    } catch (error) {
        console.error('Error fetching images:', error);
        res.status(500).json({ error: '画像の取得中にエラーが発生しました' });
    }
});


// デプロイ環境で使用。appをエクスポート、ローカル環境ではコメントアウトすること
module.exports = app;

// localでは、ここでサーバーを起動させます

// app.listen(PORT, '0.0.0.0', () => {
//     console.log(`Server is running on port ${PORT}`);
// });