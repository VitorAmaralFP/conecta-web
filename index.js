const express = require("express");
const cors = require("cors");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const mysql = require("mysql");
const bcrypt = require("bcrypt");

const app = express();
const saltRounds = 10;

// Configuração do banco de dados MySQL
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    connectTimeout: 30000,
    ssl: {
        rejectUnauthorized: false,
    },
});

app.set("trust proxy");

// Middlewares
app.use(express.json());
app.use(cookieParser());
app.use(bodyParser.json());
app.use(
    session({
        secret: "secret", // Alterar para um valor seguro em produção
        resave: false, // Garante que a sessão seja salva mesmo sem alterações
        saveUninitialized: false,
        cookie: {
            secure: true,
            maxAge: 1000 * 60 * 60 * 24, // 1 dia
            sameSite: 'none'
        },
    })
);
app.use(
    cors({
        origin: ["https://elaborate-sopapillas-067537.netlify.app"],
        methods: ["POST", "GET", "PUT"],
        credentials: true, // Garante o envio de cookies
    })
);

// Log para depuração de sessão
app.use((req, res, next) => {
    console.log("Sessão atual:", req.session);
    next();
});

// Rotas
app.post("/register", (req, res) => {
    try {
        const { email, password } = req.body;

        db.query("SELECT * FROM users WHERE email = ?", [email], (err, result) => {
            if (err) {
                return res.status(400).json({ message: "Erro no servidor", error: err });
            }

            if (result.length === 0) {
                bcrypt.hash(password, saltRounds, (err, hash) => {
                    db.query("INSERT INTO users (email, password) VALUES (?, ?)", [email, hash], (err, result) => {
                        if (err) {
                            return res.status(400).json({ message: "Erro ao cadastrar usuário", err });
                        }

                        return res.status(200).json({ message: "Cadastrado com sucesso", result });
                    });
                });
            } else {
                return res.status(400).json({ message: "Email já cadastrado" });
            }
        });
    } catch (error) {
        console.error("Erro inesperado:", error);
        return res.status(500).json({ message: "Erro inesperado", error });
    }
});

app.post("/login", (req, res) => {
    const { email, password } = req.body;

    db.query("SELECT * FROM users WHERE email = ?", [email], (err, result) => {
        if (err) {
            return res.status(400).json({ message: "Erro no login", error: err });
        }

        if (result.length > 0) {
            bcrypt.compare(password, result[0].password, (err, hashed) => {
                if (err) {
                    console.error("Erro ao comparar senhas:", err);
                    return res.status(500).json({ message: "Erro no servidor" });
                }
                if (hashed) {
                    req.session.email = result[0].email; // Armazena o email na sessão
                    req.session.save((err) => {
                        if (err) {
                            console.error("Erro ao salvar sessão:", err);
                            return res.status(500).json({ message: "Erro ao salvar sessão" });
                        }
                        console.log("Sessão salva com sucesso:", req.session);
                        return res.status(200).json({ message: "Logado com sucesso", login: true });
                    });
                } else {
                    return res.status(401).json({ message: "Senha incorreta", login: false });
                }
            });
        } else {
            return res.status(404).json({ message: "Usuário não encontrado" });
        }
    });
});

app.get("/", (req, res) => {
    console.log("Verificando sessão no endpoint '/':", req.session);
    if (req.session.email) {
        return res.json({ valid: true, email: req.session.email });
    } else {
        return res.json({ valid: false });
    }
});

app.get("/list-companies", (req, res) => {
    if (!req.session.email) {
        return res.status(401).json({ message: "Usuário não autenticado" });
    }

    const query = `
        SELECT 
            companies.id,
            companies.cnpj,
            companies.name,
            companies.contact,
            companies.adress,
            companies.company_sector,
            companies.is_partner,
            stg.name AS ods_name,
            users.email AS user_email
        FROM companies
        LEFT JOIN stg ON companies.stg_id = stg.stg_id
        LEFT JOIN users ON companies.user_id = users.id
    `;

    db.query(query, (err, result) => {
        if (err) {
            console.error("Erro ao consultar empresas:", err);
            return res.status(500).json({ message: "Erro ao buscar empresas." });
        }

        return res.status(200).json(result);
    });
});

// Configuração do servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server listening on ${PORT}`);
});
