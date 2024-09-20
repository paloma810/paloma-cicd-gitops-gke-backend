const express = require('express')
const bodyParser = require('body-parser')
const cors = require('cors')
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const winston = require('winston');

/* add google-cloud component */
require('@google-cloud/trace-agent').start({
  projectId: 'kh-paloma-m01-01',
});
require('@google-cloud/profiler').start({
    projectId: 'kh-paloma-m01-01',
    serviceContext: {
        service: 'sample-app-back',
        version: '1.0.0'
    },
});

const app = express()
const jwtsSecretKey = 'your-secret-key'; // 秘密鍵は安全に保管する必要があります
const db = process.env.POSTGRES_DB
const db_user = process.env.POSTGRES_USER
const db_password = process.env.POSTGRES_PASSWORD
const db_host = process.env.POSTGRES_SERVER
const db_port = process.env.POSTGRES_PORT

const pool = new Pool({
  user: db_user,
  host: db_host,
  database: db,
  password: db_password,
  port: db_port, // デフォルトのPostgreSQLポート
});

// ログの出力先を指定
const logger = winston.createLogger({
  transports: [
    new winston.transports.Console(),  // コンソールにログを出力
    new winston.transports.File({
      filename: '/app/log/backend.log',  // ファイルにログを出力
      level: 'info',  // ログのレベルを指定 (info レベル以上のものがファイルに出力される)
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()  // JSON形式でログを出力
      )
    })
  ]
});

app.use(bodyParser.json())
app.use(cors())

app.post('/test', function(req, res) {
  if(req.body.id == 'test' && req.body.pass == 'test'){
    res.send({
      message: 'OK'
    })
  }else{
    res.send({
      message: '認証エラー'
    })
  }
 
})

// 認証エンドポイント
app.post('/api/authenticate', async (req, res) => {
  const { username, password } = req.body;

  try {
    logger.info('start authenticate')
    // ユーザが存在するか確認
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

    //if (result.rows.length === 0 || password != result.rows[0].password) {
    if (result.rows.length === 0 || !bcrypt.compareSync(password, result.rows[0].password)) {
      logger.info('the user not exists in DB or password is incorrect.')
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // トークンの生成
    const jwtPayload = {
      userId: result.rows[0].user_id,
      username: result.rows[0].username,
    };
    const jwtOptions = {
      algorithm: 'HS256',
      expiresIn: '10m',
    };

    const token = jwt.sign(jwtPayload, jwtsSecretKey, jwtOptions);

    logger.info('login succeed. return jwt token')
    res.json({
      token: token,
      message: "Login successful"
    });

  } catch (error) {
    logger.error(`Error during authentication: ${error}`);
    console.error('Error during authentication:', error);
    res.status(500).json({
      token: null,
      message: 'Internal Server Error' });
  }
});

// サーバーの起動
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logger.info(`Server is running on port ${PORT}`);
});
