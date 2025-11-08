import express from "express";
import dotenv from "dotenv";

import cors from 'cors'
import helmet from "helmet";
import cookieParser from "cookie-parser";
import http from 'http'

import allowAccess from './backend/config/cors.js'
import apiRoutes from './backend/routes/mainRoutes.js'

const app = express()

const server = http.createServer(app)


app.set("trust proxy", 1) //For Render

dotenv.config()


//middleware
app.use(express.json())
app.use(cookieParser())


// CORS set-up
app.use(cors( 
    {
        origin : function(origin, callback){
            if( !origin || allowAccess.includes(origin)){
                callback(null, true)
            }else callback( new Error('Site not allowed by CORS'))
        },
        method : ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'],
        credentials : true
    }))

// helmet setup
if (process.env.NODE_ENV === 'production'){
    app.use(helmet())
} else{
    app.use(helmet({
        contentSecurityPolicy :{
            useDefaults : true,
            'script-src' : ['self', 'unsafe-inlie']
        }
    }))
}

app.use('/v1', apiRoutes)

const PORT = process.env.APP_PORT


app.get('/', (req, res)=>{
    res.status(200).json('Welcome to Stitch ')
})


// Render deployment
app.get("/healthz", (req, res) => res.send("OK"));


server.listen(PORT, ()=>{
    console.log(`Server actively running on http://localhost:${PORT}`)
})



// Catch invalid route
app.use((req, res)=>{
    res.status(404).json({
        success : false,
        error : " Route not found"
    })
})


//Error handling
app.use((err, req, res, next)=>{
    if (err) console.log('From Error Handler', err.stack)
    res.status(500).json({
        success : false,
        error : " Internal server error"
    })
})










