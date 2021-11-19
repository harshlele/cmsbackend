import express from "express";
import bodyParser from "body-parser";
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

app.use(cookieParser());
app.use(
  session({
    secret: crypto.randomBytes(20).toString("hex"),
    saveUninitialized: true,
    cookie: { maxAge: 86400000 }, // 1 day
    resave: false,
  })
);

app.listen(4000, () => {
  console.log("YO AM LISTENING!");
});

app.use((req, res, next) => {
  
  if (
    req.url.includes("admin") &&
    !req.url.includes("login") &&
    !req.session.isAuth
  ) {
    return res.status(401).end();
  } else next();
  
});

app.post("/admin/blogs", (req, res) => {
  return res.json({ status: 1, msg: "you have successfully auth uwu" });
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
  else if (req.body.scope == "login") {
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
        req.session.user = req.body.user;
        return res.json({ status: 1, msg: "logged in! :D" });
      } else return res.json({ status: 0, msg: "wrong password D:" });
    } catch (e) {
      return res.json({ status: 0, msg: "error while signing up - " + e });
    }
  } else if (req.body.scope == "logout") {
    req.session.destroy();
    return res.json({status: 1, msg: "logged out"});
  }
});

process.on("beforeExit", (code) => {
  pool.end();
});
