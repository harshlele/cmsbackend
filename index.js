import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import pg from "pg";
import bcrypt from "bcryptjs";
import cookieParser from "cookie-parser";
import session from "express-session";
import crypto from "crypto";

const { Pool } = pg;

const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "cmsapp",
  password: "6700",
  port: 5432,
});

pool.on("error", (err, client) => {
  console.error("Unexpected error on idle client", err);
  process.exit(-1);
});

const app = express();
app.use(bodyParser.json());
app.use(cors());
app.use(cookieParser());
app.use(
  session({
    secret: crypto.randomBytes(20).toString("hex"),
    saveUninitialized: true,
    cookie: { maxAge: 86400000, domain: "http://localhost:4000" }, // 1 day
    resave: false,
  })
);

app.listen(4000, () => {
  console.log("YO AM LISTENING!");
});

app.post("/auth", async (req, res) => {
  if (req.body.scope === "signup") {
    const client = await pool.connect();

    try {
      let r = await client.query("SELECT * FROM users where username = $1", [
        req.body.user,
      ]);
      if (r.rows.length)
        return res.json({
          status: 0,
          msg: `user ${req.body.user} already exists`,
        });

      const hash = await bcrypt.hash(req.body.pass, 10);

      await client.query(
        'INSERT into users("username","passwd") VALUES($1,$2)',
        [req.body.user, hash]
      );
      client.release();

      return res.json({ status: 1, msg: `user ${req.body.user} added` });
    } catch (e) {
      return res.json({ status: 0, msg: "error while signing up - " + e });
    }
  }

  if (req.body.scope == "login") {
    const client = await pool.connect();

    try {
      let r = await client.query(
        "SELECT passwd FROM users where username = $1",
        [req.body.user]
      );
      client.release();

      if (r.rows.length == 0)
        return res.json({
          status: 0,
          msg: `user ${req.body.user} does not exist`,
        });

      let hash = r.rows[0].passwd;

      let match = await bcrypt.compare(req.body.pass, hash);
      if (match) {
        req.session.isAuth = true;
        return res.json({ status: 1, msg: "logged in! :D" });
      } else return res.json({ status: 0, msg: "wrong password D:" });
    } catch (e) {
      return res.json({ status: 0, msg: "error while signing up - " + e });
    }
  }
});

app.post("/api", (req, res) => {
  console.log(req.session);
  if (req.session) {
    res.json({ status: 1, msg: "user logged in :)" });
  } else res.redirect("/login");
});

process.on("beforeExit", (code) => {
  pool.end();
});
