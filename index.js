const express = require("express");
const cors = require("cors");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const mysql = require("mysql");
const app = express();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const saltRounds = 10;

const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10, // Número máximo de conexões no pool
    connectTimeout: 30000, // Aumenta o tempo limite para 30 segundos
    ssl: {
        rejectUnauthorized: false, // Necessário para bancos que exigem SSL (como Azure)
    },
});

app.use(express.json())
app.use(cors({
    origin: ["https://elaborate-sopapillas-067537.netlify.app"],
    methods: ["POST", "GET", "PUT"],
    credentials: true,
}))
app.use(cookieParser())
app.use(bodyParser.json())
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        maxAge: 1000 * 60 * 60 * 24
    }
}))

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) return res.status(401).json({ message: "Token não fornecido" });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: "Token inválido" });
        req.user = user;
        next();
    });
};

app.post("/register", authenticateToken, (req, res) => {
    try {
        const { email, password } = req.body;

        db.query("SELECT * FROM users WHERE email = ?", [email], (err, result) => {
            if (err) {
                res.status(400).json({ message: `error` })
            }

            if (result.length === 0) {
                bcrypt.hash(password, saltRounds, (err, hash) => {
                    db.query("INSERT INTO users (email, password) VALUES (?, ?)", [email, hash], (err, result) => {
                        if (err) {
                            res.status(400).json({ message: 'Erro no cadastro', err })
                        }

                        res.status(200).json({ message: "Cadastrado com sucesso", result })
                    })
                })
            } else {
                res.status(400).json({ message: "Email já cadastrado" })
            }
        })
    } catch (error) {
        console.log(err);
    }
})

app.post("/register-company", authenticateToken, async (req, res) => {
    const { name, contact, address, cnpj, area, email, ods } = req.body;

    try {
        const userQuery = "SELECT id FROM users WHERE email = ?";
        db.query(userQuery, [email], (userErr, userResult) => {
            if (userErr) {
                return res.status(500).json({ message: "Erro ao buscar usuário." });
            }

            if (userResult.length === 0) {
                return res.status(400).json({ message: "Usuário não encontrado." });
            }

            const userId = userResult[0].id;

            const stgQuery = "SELECT stg_id FROM stg WHERE name = ?";
            db.query(stgQuery, [ods], (stgErr, stgResult) => {
                if (stgErr) {
                    return res.status(500).json({ message: "Erro ao buscar ODS." });
                }

                let stgId;

                if (stgResult.length === 0) {
                    const createStgQuery = "INSERT INTO stg (name, companies_quantity) VALUES (?, ?)";
                    db.query(createStgQuery, [ods, 0], (createStgErr, createStgResult) => {
                        if (createStgErr) {
                            return res.status(500).json({ message: "Erro ao criar ODS." });
                        }

                        stgId = createStgResult.insertId;

                        registerCompany(userId, stgId);
                    });
                } else {
                    stgId = stgResult[0].stg_id;

                    registerCompany(userId, stgId);
                }
            });

            const registerCompany = (userId, stgId) => {
                const companyQuery = `
                    INSERT INTO companies (cnpj, name, contact, adress, company_sector, stg_id, user_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                `;

                db.query(
                    companyQuery,
                    [cnpj, name, contact, address, area, stgId, userId],
                    (companyErr) => {
                        if (companyErr) {
                            return res.status(500).json({ message: "Erro ao registrar empresa." });
                        }
                        const updateStgQuery = "UPDATE stg SET companies_quantity = companies_quantity + 1 WHERE stg_id = ?";
                        db.query(updateStgQuery, [stgId]);

                        res.status(200).json({ message: "Empresa registrada com sucesso!" });
                    }
                );
            };
        });
    } catch (error) {
        res.status(500).json({ message: "Erro inesperado.", error });
    }
});


app.post("/login", authenticateToken, (req, res) => {
    const { email, password } = req.body;

    db.query("SELECT * FROM users WHERE email = ?", [email], (err, result) => {
        if (err) {
            return res.status(400).json({ message: "Erro no login" });
        }
        if (result.length > 0) {
            bcrypt.compare(password, result[0].password, (err, hashed) => {
                if (err) {
                    console.error("Erro ao comparar senhas:", err);
                    return res.status(500).json({ message: "Erro no servidor" });
                }
                if (hashed) {
                    const token = jwt.sign(
                        { email: result[0].email, id: result[0].id },
                        process.env.JWT_SECRET,
                        { expiresIn: "1d" } // Expira em 1 dia
                    );
                    return res.status(200).json({ message: "Logado com sucesso", token });
                } else {
                    return res.status(401).json({ message: "Senha incorreta" });
                }
            });
        } else {
            return res.status(404).json({ message: "Usuário não encontrado" });
        }
    });
});

app.get('/', authenticateToken, (req, res) => {
    if (req.session.email) {
        return res.json({ valid: true, email: req.session.email })
    } else {
        return res.json({ valid: false })
    }
})

app.get('/list-companies', authenticateToken, (req, res) => {
    try {
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
    } catch (error) {
        console.error("Erro inesperado:", error);
        return res.status(500).json({ message: "Erro inesperado no servidor." });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server listening on 3001`);
});

db.getConnection(function (err, con) {
    if (err) {
        console.log(err);
    } else {
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

        con.query(sqlUsers, (err, result) => {
            con.release();

            if (err) {
                console.log("Erro ao criar tabela 'users':", err);
            } else {
                console.log("'users' criada com sucesso");

                con.query(sqlStg, (err, result) => {
                    if (err) {
                        console.log("Erro ao criar tabela 'stg':", err);
                    } else {
                        console.log("'stg' criada com sucesso");

                        con.query(sqlCompanies, (err, result) => {
                            if (err) {
                                console.log("Erro ao criar tabela 'companies':", err);
                            } else {
                                console.log("'companies' criada com sucesso");
                            }
                        });
                    }
                });
            }
        });
    }
});