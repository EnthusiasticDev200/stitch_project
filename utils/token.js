import jwt from 'jsonwebtoken'
import dotenv from 'dotenv'

dotenv.config()

const generateToken = {
    accessToken : function(payload){
        const token = jwt.sign(
            payload,
            process.env.JWT_SECRET,
            {
                algorithm: 'HS256',
                'expiresIn' : '5m'
            }
        )
        return token
    },

    refreshToken : function(payload){
        const newToken = jwt.sign(
            payload,
            process.env.REFRESH_JWT_SECRET,
            {
                algorithm: 'HS256',
                'expiresIn' : '24h'
            }
        )
        return newToken
    }

}

export default generateToken