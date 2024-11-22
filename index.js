const express = require("express");
const cors = require("cors");
const session = require("express-session"); // Removendo Redis
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

// Middlewares
app.use(express.json());
app.use(
    cors({
        origin: ["https://elaborate-sopapillas-067537.netlify.app"],
        methods: ["POST", "GET", "PUT"],
        credentials: true,
    })
);
app.use(cookieParser());
app.use(bodyParser.json());
app.use(
    session({
        secret: "secret", // Alterar para um valor seguro em produção
        resave: false,
        saveUninitialized: false,
        cookie: {
            secure: true, // Ativa cookies seguros apenas em produção
            httpOnly: true, // Protege contra ataques XSS
            maxAge: 1000 * 60 * 60 * 24, // 1 dia
        },
    })
);

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

// Configuração do banco de dados
db.getConnection((err, con) => {
    if (err) {
        console.error("Erro ao conectar ao banco de dados:", err);
        return;
    }

    console.log("Conexão com o banco de dados estabelecida!");

    const sqlUsers = `
        CREATE TABLE IF NOT EXISTS users (
            id INT PRIMARY KEY AUTO_INCREMENT,
            email VARCHAR(50) NOT NULL,
            password VARCHAR(1000) NOT NULL
        );
    `;

    const sqlStg = `
        CREATE TABLE IF NOT EXISTS stg (
            stg_id INT PRIMARY KEY AUTO_INCREMENT,
            name VARCHAR(100) NOT NULL,
            companies_quantity INT
        );
    `;

    const sqlCompanies = `
        CREATE TABLE IF NOT EXISTS companies (
            id INT PRIMARY KEY AUTO_INCREMENT,
            cnpj VARCHAR(50) UNIQUE NOT NULL,
            name VARCHAR(100) NOT NULL,
            contact VARCHAR(50) NOT NULL,
            adress VARCHAR(100) NOT NULL,
            company_sector VARCHAR(50) NOT NULL,
            is_partner INT NOT NULL DEFAULT 0,
            stg_id INT,
            user_id INT,
            FOREIGN KEY (stg_id) REFERENCES stg(stg_id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    `;

    con.query(sqlUsers, (err) => {
        if (err) {
            console.error("Erro ao criar tabela 'users':", err);
        } else {
            console.log("Tabela 'users' criada com sucesso.");
        }
    });

    con.query(sqlStg, (err) => {
        if (err) {
            console.error("Erro ao criar tabela 'stg':", err);
        } else {
            console.log("Tabela 'stg' criada com sucesso.");
        }
    });

    con.query(sqlCompanies, (err) => {
        if (err) {
            console.error("Erro ao criar tabela 'companies':", err);
        } else {
            console.log("Tabela 'companies' criada com sucesso.");
        }
    });
});
