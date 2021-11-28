import bcrypt from "bcryptjs";

export default {
  async authorise(req, res, pool) {
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
      return res.json({ status: 1, msg: "logged out" });
    }
    else if (req.body.scope == "change_password") {
      const client = await pool.connect();

      try {
        let r = await client.query(
          "SELECT passwd FROM users where username = $1",
          [req.body.user]
        );

        if (r.rows.length == 0) {
          client.release();
          return res.json({ status: 0, msg: "User does not exist" });
        }

        let hash = r.rows[0].passwd;

        let match = await bcrypt.compare(req.body.pass, hash);

        if (match) {
          const newHash = await bcrypt.hash(req.body.new_pass, 10);

          let r2 = await client.query(
            "UPDATE users SET passwd = $1 WHERE username = $2",
            [newHash, req.body.user]
          );

          req.session.destroy();
          return res.json({ status: 1, msg: "Password changed" })

        } else {
          client.release();
          return res.json({ status: 0, msg: "Please enter correct existing password" })
        };


      } catch (e) {
        return res.json({ status: 0, msg: "error while changing password - " + e });
      }

    }
  },

  adminAuthorise(req, res, next) {
    if (
      req.url.includes("admin") &&
      !req.url.includes("login") &&
      !req.session.isAuth
    ) {
      return res.status(401).end();
    } else next();

  }
}
