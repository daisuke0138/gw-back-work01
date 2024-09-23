// api/index.js
const app = require('./server');

// VercelのServerless FunctionとしてExpressアプリをエクスポート
module.exports = (req, res) => {
    // Expressにリクエストとレスポンスを渡して処理
    app(req, res);
};