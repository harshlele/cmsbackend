import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import pg from 'pg';
import bcrypt from 'bcryptjs';

const {Pool} = pg;

const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'cmsapp',
    password: '6700',
    port: 5432,
});

pool.on('error', (err, client) => {
    console.error('Unexpected error on idle client', err)
    process.exit(-1)
})
  

const app = express();
app.use(bodyParser.json());
app.use(cors());



app.listen(4000,() => {
    console.log('YO AM LISTENING!');
});

app.post('/auth',async (req,res) => {
    if(req.body.scope === 'signup'){
        const client = await pool.connect();
        
        try{
            let r = await client.query('SELECT * FROM users where user = $1',[req.body.user]);
            if(r.rows.length) return res.json({status: 0,msg: 'user already exists'});
            
            const hash = await bcrypt.hash(req.body.pass,10);

            r = await client.query('INSERT into users("user","passwd") VALUES($1,$2)',[req.body.user,hash]);
            let a = 1;
            
            client.release();
            return {status: 1, msg: 'user added'};
        }
        catch(e){
            return res.json({status: 0,msg: 'error while signing up - ' + e});
        }
        


    }
});

process.on('beforeExit',(code) => {
    pool.end();
});