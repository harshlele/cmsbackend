import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import cookieParser from "cookie-parser";
import session from "express-session";
import crypto from "crypto";
import auth from "./util/auth.js";

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

app.use(auth.adminAuthorise);

app.post("/admin/blogs", (req, res) => {
  return res.json({ status: 1, msg: "you have successfully auth uwu" });
});

app.post("/auth", async (req, res) => {
  return auth.authorise(req, res, pool);
});

process.on("beforeExit", (code) => {
  pool.end();
});
