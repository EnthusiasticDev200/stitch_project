import Redis from "ioredis";
import { Queue, Worker } from "bullmq";
import dotenv from 'dotenv'

import {sendOtpEmail, emailVerification} from "./mailer.js";

dotenv.config()


let connection;
if (process.env.NODE_ENV === 'development'){
    console.log('Worker actively on DevZone')
    connection = new Redis('127.0.0.1:6379', { maxRetriesPerRequest: null})
} else {
    connection = new Redis(process.env.REDIS_URL,{maxRetriesPerRequest : null })
}


const otpQueue = new Queue('otp-emails', {connection})

const otpWorker = new Worker('otp-emails', 
    async job =>{
        const { email, otp } = job.data
        await sendOtpEmail(email, otp)
    }, {connection})

const verifyEmailQueue = new Queue('verify-email', {connection})

const verifyEmailWoker = new Worker('verify-email',
    async job =>{
        const { email, otp } = job.data
        await emailVerification( email, otp, 'admin')
    }, {connection}
)

export { otpQueue, verifyEmailQueue}










