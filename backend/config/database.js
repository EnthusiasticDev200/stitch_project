import dotenv from 'dotenv'
import pg from 'pg'

dotenv.config()
const { Pool } = pg

let db
if(process.env.NODE_ENV === 'development'){
    console.log('DB on DevRoll')
    db = new Pool({
    user: process.env.DEV_DB_USERNAME,
    password: process.env.DEV_DB_PASSWORD,
    host: process.env.DEV_DB_HOST,
    port: process.env.DEV_DB_PORT,
    database: process.env.DEV_DB_NAME,
});

}
 

export default db