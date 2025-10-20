import Redis from "ioredis";
import { Queue, Worker } from "bullmq";
import dotenv from 'dotenv'

import sendOtpEmail from "./mailer.js";

dotenv.config()


let connection;
if (process.env.NODE_ENV === 'development'){
    console.log('Worker actively on DevZone')
    connection = new Redis({
        host: '127.0.0.1', port : 6379
    }, {maxRetriesPerRequest : null})
}

const otpQueue = new Queue('otp-emails', {connection})

const otpWorker = new Worker('otp-emails', 
    async job =>{
        const { otp, email } = job.data
        await sendOtpEmail(otp, email)
    }, {connection})


export default otpQueue










