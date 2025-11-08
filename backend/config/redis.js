import dotenv from 'dotenv'

import Redis from 'ioredis'

dotenv.config()

let redis

if(process.env.NODE_ENV === 'development'){
    console.log('Redis on DevZone')
    redis = new Redis({
        host : '127.0.0.1',
        port : '6379'
    })
} else{
  console.log('Redis runnning on PRODUCTION!')
  redis = new Redis(prodRedis, {
    tls: prodRedis?.startsWith('rediss://') ? {} : undefined // hits redis internal url
  })
}
  







export default redis

